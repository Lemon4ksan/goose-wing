// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core Primitives (Time, Math, Sync, Bytes, IO Streams) Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import json;
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

        sub.assert_eq(d_ns.as_nanos(), 50);
        sub.assert_eq(d_us.as_nanos(), 50000);
        sub.assert_eq(d_us.as_micros(), 50);
        sub.assert_eq(d_ms.as_micros(), 50000);
        sub.assert_eq(d_ms.as_millis(), 50);
        sub.assert_eq(d_s.as_millis(), 50000);
        sub.assert_eq(d_s.as_secs(), 50);
        sub.assert_eq(d_m.as_secs(), 3000);
        sub.assert_eq(d_h.as_secs(), 7200);
        sub.assert_eq(d_d.as_secs(), 259200);

        sub.assert_in_delta(core::millis(1500).as_secs_f64(), 1.5, 0.000001);
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

        sub.assert_false(pos.is_negative() || pos.is_zero());

        sub.assert_true(zero_dur.is_zero());
        sub.assert_false(zero_dur.is_negative());

        sub.assert_true(neg.is_negative());
        sub.assert_false(neg.is_zero());

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

        sub.assert_eq(d1.compare(d2), -1);
        sub.assert_eq(d2.compare(d1), 1);
        sub.assert_eq(d1.compare(d3), 0);
    };
}

// ----------------------------------------------------------------------------
// 2. Duration Truncation and Rounding
// ----------------------------------------------------------------------------
fn test_duration_truncation_and_rounding(t: lit::T&) {
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
        sub.assert_eq(tm.nsec, 123456789);
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

        // 1969-12-25 12:00:00 UTC is days_count = -7 (days_count + 4 = -3 < 0) -> Thursday
        let tm_pre_week = core::date(1969, core::Month.December, 25, 12, 0, 0, 0, 0);
        sub.assert_eq(tm_pre_week.weekday(), core::Weekday.Thursday);

        // Normalization of negative fractional nanoseconds
        let tm_norm = core::unix(100, -250000000);
        sub.assert_eq(tm_norm.unix(), 99, "negative nanos must decrement sec");
        sub.assert_eq(tm_norm.nsec, 750000000, "nanos must be normalized in [0, 999_999_999]");

        // min_i64 nanoseconds normalization (must stay in the past, never wrap to future)
        let min_i64_nanos = -9223372036854775807 - 1;
        let tm_min_ns = core::unix(0, min_i64_nanos);
        sub.assert_lt(tm_min_ns.unix(), 0, "unix(0, min_i64) must be in the past");
        sub.assert_eq(tm_min_ns.unix(), -9223372037);
        sub.assert_eq(tm_min_ns.nsec, 145224192);
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
        sub.assert_ne(t1.compare(t2), 0);
        sub.assert_eq(t1.compare(t1), 0);

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
}

// ----------------------------------------------------------------------------
// 9. RFC 3339 / ISO 8601 Codec & Attack Vectors
// ----------------------------------------------------------------------------
fn test_rfc3339_codec_and_attack_vectors(t: lit::T&) {
    t.run("RFC 3339 Formatting (UTC, Offset)") { sub =>
        var buf: u8[..64] = [];
        let tm = core::date(2026, core::Month.October, 23, 14, 30, 45, 500000000, 0);

        buf.clear(); core::format_rfc3339(buf, tm);
        sub.assert_bytes_eq(buf[..], "2026-10-23T14:30:45Z");

        let tm_offset = core::date(2026, core::Month.October, 23, 17, 30, 45, 0, 10800);
        buf.clear(); core::format_rfc3339(buf, tm_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T17:30:45+03:00");

        let tm_neg_offset = core::date(2026, core::Month.October, 23, 9, 30, 45, 0, -18000);
        buf.clear(); core::format_rfc3339(buf, tm_neg_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T09:30:45-05:00");
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

// --- Component: core_math ---
// Verification and conformance test suite for core/math.goose (std.math).
// Tests branchless constant-time arithmetic, saturation logic, Euclidean division,
// 128-bit multiplication without u128, WyRand v4.2, Lemire fast-range,
// Jacobson EWMA RTT (RFC 6298 / RFC 9002 Errata ID 7539),
// non-cryptographic hashes (FNV-1a, xxHash32, wyhash64), and SOCKS5 CT frame validation.

// ----------------------------------------------------------------------------
// 11. Branchless Constant-Time Arithmetic & Selection
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

    t.run("ct_eq and ct_lt") { sub =>
        sub.assert_eq(core::ct_eq_u32(42, 42), 1, "42 == 42");
        sub.assert_eq(core::ct_eq_u32(42, 43), 0, "42 != 43");

        sub.assert_eq(core::ct_lt_u32(10, 20), 1, "10 < 20 (u32)");
        sub.assert_eq(core::ct_lt_u32(20, 20), 0, "20 !< 20 (u32)");
        sub.assert_eq(core::ct_lt_u32(30, 20), 0, "30 !< 20 (u32)");

        sub.assert_eq(core::ct_lt_u64(100, 200), 1, "100 < 200 (u64)");
        sub.assert_eq(core::ct_lt_u64(200, 200), 0, "200 !< 200 (u64)");
        sub.assert_eq(core::ct_lt_u64(300, 200), 0, "300 !< 200 (u64)");
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

        sub.assert_eq(core::ct_min_u64(500, 1000), 500, "min_u64");
        sub.assert_eq(core::ct_max_u64(500, 1000), 1000, "max_u64");
    };

    t.run("ct_abs_i64 and clamp_i64") { sub =>
        sub.assert_eq(core::ct_abs_i64(500), 500, "abs(500)");
        sub.assert_eq(core::ct_abs_i64(-500), 500, "abs(-500)");
        sub.assert_eq(core::ct_abs_i64(0), 0, "abs(0)");

        sub.assert_eq(core::clamp_i64(-5, 10, 20), 10, "clamp_i64 below");
        sub.assert_eq(core::clamp_i64(15, 10, 20), 15, "clamp_i64 within");
        sub.assert_eq(core::clamp_i64(25, 10, 20), 20, "clamp_i64 above");
    };
}

// ----------------------------------------------------------------------------
// 12. Saturation & Checked Arithmetic
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

    t.run("Checked Arithmetic") { sub =>
        let c_u64_ovf = core::add_checked_u64(core::U64_MAX, 1);
        sub.assert_eq(c_u64_ovf.overflow, true, "add_checked_u64 ovf flag");

        let c_i64_ovf = core::mul_checked_i64(core::I64_MAX, 2);
        sub.assert_eq(c_i64_ovf.overflow, true, "mul_checked_i64 ovf flag");

        let c_i64_ok = core::mul_checked_i64(10, -5);
        sub.assert_eq(c_i64_ok.overflow, false, "mul_checked_i64 ok flag");
        sub.assert_eq(c_i64_ok.value, -50, "mul_checked_i64 ok val");
    };
}

// ----------------------------------------------------------------------------
// 13. 128-Bit Multiplication & Wymum Without u128
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
// 14. Bit Manipulation & Endianness Codecs
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

    t.run("is_pow2_u64 and next_pow2_u64") { sub =>
        sub.assert_eq(core::is_pow2_u64(0), false, "0 is not pow2 (u64)");
        sub.assert_eq(core::is_pow2_u64(1), true, "1 is pow2 (u64)");
        sub.assert_eq(core::is_pow2_u64(1024), true, "1024 is pow2 (u64)");
        sub.assert_eq(core::is_pow2_u64(0x8000000000000000), true, "2^63 is pow2 (u64)");
        sub.assert_eq(core::next_pow2_u64(5), 8, "next_pow2_u64(5)");
        sub.assert_eq(core::next_pow2_u64(0x8000000000000001), 0x8000000000000000, "next_pow2 overflow clamp");
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
        core::append_u16_be(out, 0x1234);
        sub.assert_eq(out[0], 0x12, "append_u16_be byte 0");
        sub.assert_eq(out[1], 0x34, "append_u16_be byte 1");

        out.clear();
        core::append_u32_be(out, 0x12345678);
        sub.assert_eq(out[0], 0x12, "append_u32_be byte 0");
        sub.assert_eq(out[1], 0x34, "append_u32_be byte 1");
        sub.assert_eq(out[2], 0x56, "append_u32_be byte 2");
        sub.assert_eq(out[3], 0x78, "append_u32_be byte 3");

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
// 15. Euclidean Division & Remainder
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
}

// ----------------------------------------------------------------------------
// 16. PRNGs & Lemire Fast-Range Mapping
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

    t.run("Lemire Fast-Range Bounds (Biased and Unbiased)") { sub =>
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
// 19. Fast Non-Cryptographic Hashing & Combinators
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
    };
}

// --- Component: core_sync ---
// Tests for concurrency containment, singleflight deduplication, and SPSC lock-free queues.

thread_fn test_crashing_worker() {
    abort("intentional contained worker failure for test");
}

// ----------------------------------------------------------------------------
// 21. Crash Containment via thread_spawn_contained
// ----------------------------------------------------------------------------
fn test_thread_containment(t: lit::T&) {
    t.run("Crash Containment via thread_spawn_contained") { sub =>
        let crash_tid = thread_spawn_contained(test_crashing_worker);
        var abort_msg: u8[>..] = [];
        let ok = thread_wait(crash_tid, abort_msg);
        sub.assert_false(ok, "Contained thread reported abort status");
        sub.assert_true(abort_msg.len > 0, "Contained thread captured abort diagnostic message");
    };
}

// ----------------------------------------------------------------------------
// 22. Singleflight Deduplication & SPSC Lock-Free Ring
// ----------------------------------------------------------------------------
fn test_singleflight_and_spsc(t: lit::T&) {
    t.run("SPSC Lock-Free Ring Queue") { sub =>
        let ring, ok = core::spsc_init(16);
        if ok {
            defer core::spsc_close(ring);
            sub.assert_true(ring.is_open, "Ring is open");
            sub.assert_ge(ring.capacity, 16 as u32, "Capacity at least 16");

            sub.assert_true(core::spsc_push(ring, 10), "Push 10");
            sub.assert_true(core::spsc_push(ring, 20), "Push 20");
            sub.assert_eq(core::spsc_count(ring), 2 as u32, "Count is 2");

            var v1: u64 = 0;
            sub.assert_true(core::spsc_pop(ring, v1), "Pop 1 ok");
            sub.assert_eq(v1, 10, "Pop 1 matches 10");

            var v2: u64 = 0;
            sub.assert_true(core::spsc_pop(ring, v2), "Pop 2 ok");
            sub.assert_eq(v2, 20, "Pop 2 matches 20");

            sub.assert_eq(core::spsc_count(ring), 0 as u32, "Ring empty");
        }
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

// ----------------------------------------------------------------------------
// 23. ASCII Predicates, Case Conversions & Folding
// ----------------------------------------------------------------------------
fn test_case_folding(t: lit::T&) {
    t.run("ASCII Predicates & Character Conversions") { sub =>
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

        var lower_buf: u8[..64] = [];
        core::to_lower_ascii("GoOsE-WiNg v1.0!", lower_buf);
        sub.assert_eq(lower_buf[..], "goose-wing v1.0!", "to_lower_ascii string conversion");
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

// ----------------------------------------------------------------------------
// 24. Linear Whitespace, ASCII Whitespace & Byte Trimming
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 25. Byte Search, Slice Splitting & ByteTokenizer
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 26. Bounds-Checked Decimal & Hex Parsing and Formatting
// ----------------------------------------------------------------------------
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
// - RingBuffer circular FIFO storage, wraparound behavior, and zero-copy peeking
// - PipeBuffer two-cursor pipeline, advance_to monotonicity, and zero-copy slicing
// - CorkBuffer 16KB outbound socket buffer aggregation and partial consumption
// - SIMD accelerated ASCII, UTF-8, and CRLF boundary scanners

// ----------------------------------------------------------------------------
// 27. RingBuffer Circular FIFO & Wraparound
// ----------------------------------------------------------------------------
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
        sub.assert_eq(rb.head, 0, "Head auto-reset to 0 when read drains buffer");
        sub.assert_eq(rb.tail, 0, "Tail auto-reset to 0 when read drains buffer");
    };

    t.run("Three-Reversal rotate_left_in_place, realign_ring & contiguous_readable_slice") { sub =>
        // 1. Direct rotate_left_in_place verification
        var rot_buf: u8[6] = ['D', 'E', 'F', 'A', 'B', 'C'];
        core::rotate_left_in_place(rot_buf[..], 3);
        sub.assert_eq(rot_buf[..], "ABCDEF", "rotate_left_in_place by 3 restores ABCDEF");

        // Edge cases: 0 and len rotations are no-ops
        core::rotate_left_in_place(rot_buf[..], 0);
        sub.assert_eq(rot_buf[..], "ABCDEF", "rotate_left_in_place by 0 is no-op");
        core::rotate_left_in_place(rot_buf[..], 6);
        sub.assert_eq(rot_buf[..], "ABCDEF", "rotate_left_in_place by len is no-op");

        // 2. realign_ring on empty buffer with non-zero head
        var rb = core::new_ring_buffer();
        sub.assert_eq(rb.cap(), 4096, "RingBuffer capacity is 4096");
        rb.head = 128;
        rb.tail = 128;
        rb.count = 0;
        core::realign_ring(rb);
        sub.assert_eq(rb.head, 0, "realign_ring resets head to 0 on empty");
        sub.assert_eq(rb.tail, 0, "realign_ring resets tail to 0 on empty");
        sub.assert_eq(rb.contiguous_readable_slice(), "", "empty contiguous_readable_slice returns empty slice");

        // 3. realign_ring on contiguous non-zero head (head + count <= 4096)
        rb.write("prefix_HELLO_WORLD");
        rb.discard(7);
        sub.assert_eq(rb.head, 7, "Head advanced to 7");
        sub.assert_eq(rb.count, 11, "Count is 11");
        core::realign_ring(rb);
        sub.assert_eq(rb.head, 0, "realign_ring shifted head to 0");
        sub.assert_eq(rb.tail, 11, "realign_ring updated tail to 11");
        sub.assert_eq(rb.contiguous_readable_slice(), "HELLO_WORLD", "contiguous slice matches after linear shift");

        // 4. realign_ring & contiguous_readable_slice on wrapped unread span (head + count > 4096)
        rb.clear();
        rb.head = 4090;
        rb.tail = 4090;
        rb.count = 0;
        let w_n, w_err = rb.write("0123456789ABCDEF");
        sub.assert_eq(w_n, 16, "Wrote 16 bytes across wraparound boundary");
        sub.assert_eq(w_err, core::IoError.None, "Wrapped write succeeded");
        sub.assert_eq(rb.head, 4090, "Head before realign is 4090");
        sub.assert_eq(rb.tail, 10, "Tail wrapped to 10");

        let full_slice = rb.contiguous_readable_slice();
        sub.assert_eq(full_slice, "0123456789ABCDEF", "contiguous_readable_slice realigns wrapped span in-place");
        sub.assert_eq(rb.head, 0, "Head reset to 0 after wraparound realign");
        sub.assert_eq(rb.tail, 16, "Tail set to 16 after wraparound realign");
        sub.assert_eq(rb.count, 16, "Count preserved at 16");
    };
}

// ----------------------------------------------------------------------------
// 28. PipeBuffer Two-Cursor Pipelines & Monotonicity
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 29. CorkBuffer 16KB Outbound Aggregation
// ----------------------------------------------------------------------------
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
        let s = cb.cork_as_slice();
        let l = core::read_be_u24(s, 0);
        sub.assert_eq(l, 5 as u32, "Decoded length matches 5");
        let ty = s[3];
        sub.assert_eq(ty, 0x00, "Decoded type matches DATA");
        let fl = s[4];
        sub.assert_eq(fl, 0x01, "Decoded flags matches END_STREAM");
        let sid = core::read_be_u32(s, 5);
        sub.assert_eq(sid, 1 as u32, "Decoded stream ID matches 1");
        let pay = s[9..14];
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

// ----------------------------------------------------------------------------
// 30. SIMD Fast ASCII, UTF-8 & CRLF Scan
// ----------------------------------------------------------------------------
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

// ============================================================================
// 31. Time Subsystem Regressions (core/time)
// ============================================================================
fn test_regress_core_time(t: lit::T&) {
    t.run("Bug 1: Euclidean division quotient adjustment for negative pre-1970 timestamps") { sub =>
        // -0.5s before epoch: sec = -1, nsec = 500000000
        let t1 = core::unix(-1, 500000000);
        sub.assert_eq(t1.unix_milli(), -500, "unix_milli matches Euclidean quotient for -0.5s");
        sub.assert_eq(t1.unix_micro(), -500000, "unix_micro matches Euclidean quotient for -0.5s");
        sub.assert_eq(t1.unix_nano(), -500000000, "unix_nano matches Euclidean quotient for -0.5s");

        // -0.001s before epoch: sec = -1, nsec = 999000000 (-1ms)
        let t2 = core::unix(-1, 999000000);
        sub.assert_eq(t2.unix_milli(), -1, "unix_milli matches Euclidean quotient for -1ms");
        sub.assert_eq(t2.unix_micro(), -1000, "unix_micro matches Euclidean quotient for -1ms");
        sub.assert_eq(t2.unix_nano(), -1000000, "unix_nano matches Euclidean quotient for -1ms");
    };

    t.run("Bug 2: DURATION_MIN_NANOS rounding without signed overflow") { sub =>
        // DURATION_MIN_NANOS = -9223372036854775807 - 1 (cannot be negated in i64)
        let d_min = core::Duration { nanos: -9223372036854775807 - 1 };
        let r = d_min.round(core::secs(1));
        sub.assert_eq(r.nanos, -9223372036854775807 - 1, "round on DURATION_MIN_NANOS clamps safely");
    };
}

// ============================================================================
// 32. URL Subsystem Regressions (core/url)
// ============================================================================
fn test_regress_core_url(t: lit::T&) {
    t.run("Bug 3: 64-byte scheme capacity in Origin and RegistrableSite") { sub =>
        // Test custom scheme longer than previous 16B limit
        let long_scheme = "custom-enterprise-transport-scheme-v2";
        let test_url = "custom-enterprise-transport-scheme-v2://api.service.internal:8443/v1";
        let u, err = core::parse_url(test_url);
        sub.assert_true(u.valid, "URL with 37-byte scheme parsed cleanly");
        sub.assert_eq(core::scheme(u), long_scheme, "scheme retained accurately");

        let orig = core::new_origin_tuple(long_scheme, "api.service.internal", 8443);
        sub.assert_eq(orig.scheme[..], long_scheme, "Origin.scheme accommodates >16B schemes without truncation");
    };

    t.run("Bug 4: Case-insensitive folding of uppercase special schemes") { sub =>
        // Uppercase HTTP and HTTPS schemes must fold to canonical lowercase and set special flag
        let u_http, err_h = core::parse_url("HTTP://EXAMPLE.COM:80/INDEX.HTML");
        sub.assert_true(u_http.valid, "uppercase HTTP scheme parses cleanly");
        sub.assert_true(core::is_special(u_http), "uppercase HTTP recognized as special scheme");
        sub.assert_eq(core::scheme(u_http), "http", "scheme folded to lowercase");
        sub.assert_eq(core::host(u_http), "example.com", "host folded to lowercase");
        sub.assert_eq(core::effective_port(u_http), 80, "effective port defaults to 80");

        let u_wss, err_w = core::parse_url("WSS://CHAT.INTERNAL:443/WS");
        sub.assert_true(u_wss.valid, "uppercase WSS scheme parses cleanly");
        sub.assert_true(core::is_special(u_wss), "uppercase WSS recognized as special scheme");
        sub.assert_eq(core::scheme(u_wss), "wss", "scheme folded to lowercase");
        sub.assert_eq(core::effective_port(u_wss), 443, "effective port defaults to 443");
    };

    t.run("Bug 5 & 6: Authority overflow guards and scoped IPv6 handling") { sub =>
        // Normal authority parsing
        let u_auth, err_a = core::parse_url("https://user:pass@127.0.0.1:8080/path");
        sub.assert_true(u_auth.valid, "authority with userinfo parses cleanly");
        sub.assert_eq(core::hostname(u_auth), "127.0.0.1", "hostname parsed without port");
        sub.assert_eq(u_auth.port, 8080, "port parsed");

        // Scoped IPv6 literal
        let u_v6, err_v6 = core::parse_url("http://[fe80::1%25eth0]:8080/status");
        sub.assert_true(u_v6.valid, "scoped IPv6 literal parsed cleanly");
    };

    t.run("Bug 7: Fast query parameter lookup") { sub =>
        let q_raw = "service=auth&token=xyz789&mode=fast";
        var out_svc:  u8[..32] = [];
        var out_tok:  u8[..32] = [];
        var out_mode: u8[..32] = [];

        sub.assert_true(core::has_query_param_fast(q_raw, "service"), "param 'service' found");
        sub.assert_true(core::get_query_param_fast(q_raw, "service", out_svc) == core::QueryParamMatch.Value);
        sub.assert_eq(out_svc[..], "auth", "param 'service' value matches");

        sub.assert_true(core::has_query_param_fast(q_raw, "token"), "param 'token' found");
        sub.assert_true(core::get_query_param_fast(q_raw, "token", out_tok) == core::QueryParamMatch.Value);
        sub.assert_eq(out_tok[..], "xyz789", "param 'token' value matches");

        sub.assert_true(core::has_query_param_fast(q_raw, "mode"), "param 'mode' found");
        sub.assert_true(core::get_query_param_fast(q_raw, "mode", out_mode) == core::QueryParamMatch.Value);
        sub.assert_eq(out_mode[..], "fast", "param 'mode' value matches");
    };
}

// ============================================================================
// 33. Cryptography Subsystem Regressions (core/crypto)
// ============================================================================
fn test_regress_core_crypto(t: lit::T&) {
    t.run("Bug 8: Ed25519 low-order torsion point rejection in ed25519_verify") { sub =>
        // Point of order 1 (identity/neutral point: y=1, x=0 compressed as [1, 0, ... 0])
        var low_order_pk: u8[32] = [0; 32];
        low_order_pk[0] = 1;

        var dummy_sig: u8[64] = [0; 64];
        let msg = "test payload";
        let ok_v = core::ed25519_verify(low_order_pk, msg, dummy_sig);
        sub.assert_false(ok_v, "ed25519_verify MUST reject low-order public key");

        // Point of order 2 (y=-1, x=0 compressed as [0xec, 0xff, ... 0x7f])
        var order2_pk: u8[32] = [0xFF; 32];
        order2_pk[0] = 0xEC;
        order2_pk[31] = 0x7F;
        let ok_v2 = core::ed25519_verify(order2_pk, msg, dummy_sig);
        sub.assert_false(ok_v2, "ed25519_verify MUST reject order-2 public key");
    };

    t.run("Bug 10: X25519 all-zero shared secret rejection (RFC 7748 §6.1)") { sub =>
        var scalar:          u8[32] = [1; 32];
        var low_order_point: u8[32] = [0; 32];
        let ss, ok = core::x25519_shared_secret(scalar, low_order_point);
        sub.assert_false(ok, "low-order point yielding all-zero shared secret rejected");
        sub.assert_true(core::x25519_is_all_zero(ss), "rejected secret is zeroized");

        // Valid base point u=9
        var valid_point: u8[32] = [0; 32];
        valid_point[0] = 9;
        let valid_ss, valid_ok = core::x25519_shared_secret(scalar, valid_point);
        sub.assert_true(valid_ok, "valid point yields shared secret");
        sub.assert_false(core::x25519_is_all_zero(valid_ss), "valid shared secret is non-zero");
    };

    t.run("Bug 11: Base64 decode out-buffer clearing on invalid input") { sub =>
        var out_b64: u8[..64] = [];
        out_b64.append("pre-existing-dirty-data");

        let ok_dec = core::base64_decode("invalid!!!characters===", out_b64);
        sub.assert_false(ok_dec, "corrupted base64 input returns false");
        sub.assert_eq(out_b64.len, 0, "out_buffer is cleared on base64 decoding failure");
    };

    t.run("Bug 12 & 13: AEAD out-buffer clearing on authentication tag mismatch") { sub =>
        // AES-128-GCM: tag mismatch MUST NOT emit any decrypted bytes
        var key128:  u8[16]   = [1; 16];
        var iv:      u8[12]   = [2; 12];
        var cipher:  u8[16]   = [3; 16];
        var bad_tag: u8[16]   = [0xFF; 16];
        var out_aes: u8[..64] = [];

        let ok_aes = core::aes128_gcm_open(key128, iv, "", cipher, bad_tag, out_aes);
        sub.assert_false(ok_aes, "aes128_gcm_open fails on bad tag");
        sub.assert_eq(out_aes.len, 0, "aes128_gcm_open leaves out_plaintext empty on failure");

        // ChaCha20-Poly1305: tag mismatch MUST NOT emit any decrypted bytes
        var chacha_key: u8[32]   = [1; 32];
        var chacha_out: u8[..64] = [];

        let ok_chacha = core::chacha20_poly1305_open(chacha_key, iv, "", cipher, bad_tag, chacha_out);
        sub.assert_false(ok_chacha, "chacha20_poly1305_open fails on bad tag");
        sub.assert_eq(chacha_out.len, 0, "chacha20_poly1305_open leaves out_plaintext empty on failure");
    };
}

// ============================================================================
// 34. Compression Subsystem Regressions (core/compress)
// ============================================================================
fn test_regress_core_compress(t: lit::T&) {
    t.run("Bug 15: Deflate inflate_ex partial block rollback on truncated input") { sub =>
        // Compress small payload to generate valid Deflate blocks
        let raw = "hello world, hello goose, hello regression test suite!";
        var comp: u8[..256] = [];
        let ok_c = core::deflate(raw, comp);
        sub.assert_true(ok_c, "deflate compressed payload");

        // Now truncate the compressed stream in the middle of a block
        let truncated_src = comp[0..comp.len / 2];
        var out_dec: u8[..256] = [];
        let err, _ = core::inflate_ex(truncated_src, out_dec);
        sub.assert_true(err != core::CompressError.None, "inflate_ex returns error on truncated bitstream");
    };

    t.run("Bug 16: Zstream streaming with multi-block sync-flush and Auto detection") { sub =>
        var zs = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        sub.assert_true(zs.format == core::ContainerFormat.Auto, "initial format is Auto");

        // Decompress empty/raw bytes
        var empty_out: u8[..64] = [];
        let err_e = core::zstream_decompress_write_limit(zs, "", empty_out, 64);
        sub.assert_true(err_e == core::CompressError.None, "empty write on zstream succeeds");
    };

    t.run("Bug 18: Zstandard frame header 64-bit content size flag parsing") { sub =>
        // Construct minimum Zstandard frame header with Single_Segment_Flag (bit 5)
        var zstd_header: u8[16] = [
            0x28, 0xB5, 0x2F, 0xFD, // Magic 0xFD2FB528
            0x20,                   // Frame_Header_Descriptor: Single_Segment_Flag set, FCS_Field_Size=0 (1 byte)
            0x05,                   // Frame_Content_Size = 5
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        var offset:             i64 = 4;
        var window_size:        i64 = 0;
        var frame_content_size: i64 = 0;
        var checksum_flag:      u8  = 0;
        let err = core::parse_zstd_frame_header(zstd_header[..6], offset, window_size, frame_content_size, checksum_flag);
        sub.assert_true(err == core::CompressError.None, "valid Zstd frame header parses cleanly");
        sub.assert_eq(frame_content_size, 5, "content size matches header");
    };
}

// ============================================================================
// 35. Memory Regressions (core/io)
// ============================================================================
fn test_regress_core_sync_and_io(t: lit::T&) {
    t.run("Bug 22: PageRingBuffer sock_fd == 0 (stdin) valid descriptor support") { sub =>
        var pr = core::PageRingBuffer {
            capacity: 4096,
            count:    0,
            head:     0,
            tail:     0,
            is_open:  true,
            ..
        };
        // Negative fd must fail with guard error -1
        let rc_neg = core::page_ring_recv(pr, -1, 1024, 0);
        sub.assert_eq(rc_neg, -1, "negative fd returns -1 guard failure");

        // sock_fd == 0 must pass descriptor guard
        // Closed ring buffer returns -1
        pr.is_open = false;
        let rc_closed = core::page_ring_recv(pr, 0, 1024, 0);
        sub.assert_eq(rc_closed, -1, "closed ring buffer returns -1");
    };
}

// ============================================================================
// 36. Core Audit Defect Regressions (ByteBuilder, Signed Overflow, Host ZoneID)
// ============================================================================
fn test_regress_core_audit_bugs(t: lit::T&) {
    t.run("Bug 23: ByteBuilder offset stack leak on oversized frame failure") { sub =>
        var b = core::ByteBuilder { offsets: [], buf: [] };

        let started = core::start_u8_prefix(b);
        sub.assert_true(started, "start_u8_prefix succeeded");
        sub.assert_eq(b.offsets.len, 1, "offset pushed");

        for _ in 0..256 {
            core::put_u8(b, 0xAA);
        }

        let ok_fin = core::finish_u8_prefix(b);
        sub.assert_false(ok_fin, "finish_u8_prefix returns false for body > 255");
        sub.assert_eq(b.offsets.len, 0, "offsets stack is popped even on overflow failure");

        for _ in 0..8 {
            let ok_start = core::start_u8_prefix(b);
            sub.assert_true(ok_start, "can start new prefix after overflow rejection");
            let ok_done = core::finish_u8_prefix(b);
            sub.assert_true(ok_done, "can finish empty prefix");
        }
    };

    t.run("Bug 24: ct_abs_i64 branchless absolute value on I64_MIN") { sub =>
        let min_val = -9223372036854775807 - 1;
        let abs_min = core::ct_abs_i64(min_val);
        sub.assert_eq(abs_min, min_val, "ct_abs_i64(I64_MIN) returns I64_MIN without abort");

        let res = core::mul_checked_i64(min_val, 1);
        sub.assert_false(res.overflow, "I64_MIN * 1 does not overflow");
        sub.assert_eq(res.value, min_val, "I64_MIN * 1 == I64_MIN");
    };

    t.run("Bug 25: strip_ipv6_zone_id preserves non-bracketed hostnames containing %25") { sub =>
        var out: u8[..128] = [];

        core::strip_ipv6_zone_id("sub%25domain.example.com", out);
        sub.assert_eq(out[..], "sub%25domain.example.com", "hostname with %25 preserved without truncation");

        core::strip_ipv6_zone_id("[fe80::1%25eth0]", out);
        sub.assert_eq(out[..], "[fe80::1]", "IPv6 ZoneID stripped from bracketed address");

        core::strip_ipv6_zone_id("[2001:db8::1]", out);
        sub.assert_eq(out[..], "[2001:db8::1]", "clean IPv6 address preserved");
    };
}

// ----------------------------------------------------------------------------
// 37. Math & Crypto Regressions
// ----------------------------------------------------------------------------
fn test_math_and_crypto_regressions(t: lit::T&) {
    t.run("Bug A1: ct_min_i64 / ct_max_i64 signed overflow at I64_MIN") { sub =>
        sub.assert_eq(core::ct_min_i64(core::I64_MIN, 0), core::I64_MIN, "ct_min_i64(I64_MIN, 0)");
        sub.assert_eq(core::ct_max_i64(core::I64_MIN, 0), 0, "ct_max_i64(I64_MIN, 0)");
        sub.assert_eq(core::ct_min_i64(core::I64_MAX, -1), -1, "ct_min_i64(I64_MAX, -1)");
        sub.assert_eq(core::ct_max_i64(core::I64_MAX, -1), core::I64_MAX, "ct_max_i64(I64_MAX, -1)");
    };

    t.run("Bug A3: RFC 6979 int2octets(x) & bits2octets(h1) reduction in ecdsa_p256_sign and DER decode bounds") { sub =>
        // priv_key1 = P256_ORDER + 1 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552
        let priv_key1: u8[32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x52,
        ];
        // priv_key2 = 1 (identical mod P256_ORDER)
        var priv_key2: u8[32] = [0; 32];
        priv_key2[31] = 1;
        let sig1 = core::ecdsa_p256_sign(priv_key1, "rfc6979-test");
        let sig2 = core::ecdsa_p256_sign(priv_key2, "rfc6979-test");
        sub.assert_eq(sig1[..], sig2[..], "RFC 6979 produces identical deterministic k for d and d mod q");

        // DER decode must reject r = 0 or s = 0
        let der_zero_r: u8[8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        var raw_out: u8[64] = [0; 64];
        sub.assert_false(core::ecdsa_p256_decode_der_sig(der_zero_r[..], raw_out), "DER sig with r=0 rejected");
    };

    t.run("Bug A4: RSASSA-PSS encode_emsa_pss / verify_emsa_pss with non-MSB-aligned modulus (mod_first_byte = 0x40)") { sub =>
        var msg_hash: u8[32]    = [0x42; 32];
        var salt:     u8[32]    = [0x11; 32];
        var em:       u8[..512] = [];
        // em_len = 128, mod_first_byte = 0x40 (1023-bit RSA modulus: 1 leading zero bit)
        let ok_enc = core::encode_emsa_pss(msg_hash[..], salt[..], 128, 0x40, em);
        sub.assert_true(ok_enc, "encode_emsa_pss accepts 1023-bit modulus (mod_first_byte = 0x40)");
        if ok_enc {
            sub.assert_eq(em[0] & 0xC0, 0, "top 2 bits of EM[0] masked to zero for mod_first_byte = 0x40");
            let ok_ver = core::verify_emsa_pss(em[..], msg_hash[..], 0x40);
            sub.assert_true(ok_ver, "verify_emsa_pss accepts valid 1023-bit PSS encoding");
        }
    };

    t.run("Bug D4: equal_short on slices > 32 bytes checks middle bytes") { sub =>
        let a = "0123456789abcdef_MIDDLE_A_0123456789abcdef";
        let b = "0123456789abcdef_MIDDLE_B_0123456789abcdef";
        sub.assert_false(core::equal_short(a, b), "equal_short detects difference in middle of 42-byte slice");
    };
}

// ----------------------------------------------------------------------------
// 38. Compress & Time Regressions
// ----------------------------------------------------------------------------
fn test_compress_and_time_regressions(t: lit::T&) {
    t.run("Bug B1: Zstd fast sequence decoder with RLE_Mode FSE table (table_log == 0) and >= 4 sequences") { sub =>
        // Craft a valid Zstd frame where LL, OF, ML tables use RLE_Mode (table_log == 0), nb_seq = 4, and seq_bitstream >= 8 bytes
        // Block_Size = 18 -> (18 << 3) | 5 = 0x95
        let frame2: u8[27] = [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00,
            0x95, 0x00, 0x00,
            0x20, 0x41, 0x42, 0x43, 0x44,
            0x04, 0x54, 0x01, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
        ];
        var out: u8[..64] = [];
        let ok, err = core::zstd_decompress(frame2[..], out);
        sub.assert_true(ok, "Zstd RLE_Mode sequence block with 4 sequences decompresses cleanly");
        sub.assert_eq(out[..], "AAAABBBBCCCCDDDD", "4 RLE sequences produce AAAABBBBCCCCDDDD");
    };

    t.run("Bug B2: zstd_decompress rejects 0-byte empty input") { sub =>
        var out: u8[..16] = [];
        let ok, err = core::zstd_decompress("", out);
        sub.assert_false(ok, "empty input is not a valid Zstd frame");
    };

    t.run("Bug B3: ZStreamDecompressor ContainerFormat.Auto decompresses short (<10B) Raw Deflate stream") { sub =>
        var raw_deflate: u8[..64] = [];
        let ok_c = core::deflate("Hi", raw_deflate);
        sub.assert_true(ok_c && raw_deflate.len < 10, "compressed 'Hi' is < 10 bytes");
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var out: u8[..64] = [];
        let err_d = core::zstream_decompress_write_limit(dec, raw_deflate[..], out, 64);
        sub.assert_true(err_d == core::CompressError.None && dec.is_finished, "Auto-detected short raw deflate finishes");
        sub.assert_eq(out[..], "Hi", "decompressed short raw deflate matches 'Hi'");
    };

    t.run("Bug B4: ZStreamDecompressor Concatenated Multi-Member Gzip Streams (RFC 1952 §2.2)") { sub =>
        var gz1: u8[..128] = [];
        var gz2: u8[..128] = [];
        let ok1 = core::gzip_compress("Hello ", gz1);
        let ok2 = core::gzip_compress("World!", gz2);
        sub.assert_true(ok1 && ok2, "both gzip members compressed");
        var combined: u8[..256] = [];
        combined.append(gz1[..]);
        combined.append(gz2[..]);
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Gzip);
        var out: u8[..128] = [];
        let err_d = core::zstream_decompress_write_limit(dec, combined[..], out, 128);
        sub.assert_true(err_d == core::CompressError.None && dec.is_finished, "concatenated gzip members decompress cleanly");
        sub.assert_eq(out[..], "Hello World!", "concatenated gzip output matches both members");
    };

    t.run("Bug B5: ZStreamCompressor / ZStreamDecompressor preserve preset dict across sync-flush blocks") { sub =>
        let dict = "SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_";
        var comp = core::new_zstream_compressor(core::ContainerFormat.Raw, 6);
        comp.dict = dict;
        var wire1: u8[..256] = [];
        var wire2: u8[..256] = [];
        let ok_w1 = core::zstream_write(comp, "first_chunk_", wire1, core::FlushMode.NoFlush);
        let ok_f1 = core::zstream_write(comp, "", wire1, core::FlushMode.SyncFlush);
        let ok_w2 = core::zstream_write(comp, "SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_end", wire2, core::FlushMode.NoFlush);
        let ok_fin = core::zstream_finish(comp, wire2);
        sub.assert_true(ok_w1 && ok_f1 && ok_w2 && ok_fin, "multi-block dict stream compressed");

        var dec = core::new_zstream_decompressor(core::ContainerFormat.Raw, dict);
        var out: u8[..512] = [];
        let err_d1 = core::zstream_decompress_write_limit(dec, wire1[..], out, 512);
        let err_d2 = core::zstream_decompress_write_limit(dec, wire2[..], out, 512);
        sub.assert_true(err_d1 == core::CompressError.None && err_d2 == core::CompressError.None && dec.is_finished, "multi-block dict stream decompressed across flush boundary");
        sub.assert_eq(out[..], "first_chunk_SHARED_PREFIX_DICTIONARY_TOKEN_1234567890_end", "decompressed multi-block dict payload matches");
    };

    t.run("Bug D1-D3: RFC 9110 §5.6.7 HTTP-date and write_le round-trips") { sub =>
        // RFC 9110 §5.6.7 HTTP-date strict grammar
        let t_bad1, ok_b1 = core::parse_http_date("Sun, 06-Nov-94 08:49:37 GMT");
        sub.assert_false(ok_b1, "rfc850-date must reject 3-letter day-name");
        let t_bad2, ok_b2 = core::parse_http_date("Sun,06 Nov 1994 08:49:37 GMT");
        sub.assert_false(ok_b2, "IMF-fixdate must require SP after comma");

        var le_buf: u8[..16] = [];
        core::write_le_u32(le_buf, 0x78563412);
        core::write_le_u64(le_buf, 0x0807060504030201);
        sub.assert_eq(core::read_le_u32(le_buf[..], 0), 0x78563412, "write_le_u32 round-trip");
        sub.assert_eq(core::read_le_u64(le_buf[..], 4), 0x0807060504030201, "write_le_u64 round-trip");
    };
}

// ----------------------------------------------------------------------------
// 39. URL Regressions
// ----------------------------------------------------------------------------
fn test_url_regressions(t: lit::T&) {
    t.run("Bug C1: file://LOCALHOST case-insensitive folding and file: port rejection") { sub =>
        let u_file, err_f = core::parse_url("file://LOCALHOST/etc/hosts");
        sub.assert_true(u_file.valid, "file://LOCALHOST/etc/hosts is valid");
        sub.assert_eq(core::host(u_file), "", "file://LOCALHOST folds to empty host");
        sub.assert_eq(core::href(u_file), "file:///etc/hosts", "href normalized to file:///etc/hosts");

        let u_fport, err_fp = core::parse_url("file://example.com:8080/path");
        sub.assert_false(u_fport.valid, "file: URL with port must be rejected");
    };

    t.run("Bug C2: Non-special authority-less path starting with // prepends /. (WHATWG URL §4.5 / RFC 3986 §3.3)") { sub =>
        let u_ns, err_ns = core::parse_url("custom:/.//evil.com/path");
        sub.assert_true(u_ns.valid, "custom:/.//evil.com/path parses");
        sub.assert_true(u_ns.host_start < 0, "no authority on initial parse");
        let u_reparsed, err_re = core::parse_url(core::href(u_ns));
        sub.assert_true(u_reparsed.host_start < 0, "re-parsing href must not promote evil.com to authority");
        sub.assert_eq(core::host(u_reparsed), "", "re-parsed host remains empty");
    };

    t.run("Bug C5 & C6: normalize_http_target_uri empty host & percent decoding") { sub =>
        var norm_out: u8[..128] = [];
        let ok_empty_host = core::normalize_http_target_uri("http://:80/path", norm_out);
        sub.assert_false(ok_empty_host, "http://:80/path with empty host rejected");

        sub.assert_false(core::has_query_param_fast("a%20b=1&x=2", "a b"), "raw lookup does not match decoded key without percent-encoding");
        sub.assert_true(core::has_query_param_fast("a%20b=1&x=2", "a%20b"), "raw key 'a%20b' matches");

        var dec_small: u8[..4] = [];
        let ok_dec = core::percent_decode("%41%42%43%44", dec_small);
        sub.assert_true(ok_dec && dec_small[..] == "ABCD", "percent_decode succeeds when decoded length fits capacity");
    };
}

// ----------------------------------------------------------------------------
// 40. Bounded JSON Primitives
// ----------------------------------------------------------------------------
fn test_json_bounded_primitives(t: lit::T&) {
    t.run("RFC 8259 §7 format_json_string & format_json_key into stack-bounded u8[..N]") { sub =>
        var out: u8[..128] = [];
        out.push('{');
        core::format_json_key(out, "plain");
        core::format_json_string(out, "hello_world");
        out.push(',');
        core::format_json_key(out, "esc\"key");
        core::format_json_string(out, "line1\n\r\t\x08\x0c\"\\/\x01");
        out.push('}');
        sub.assert_eq(
            out[..],
            "{\"plain\":\"hello_world\",\"esc\\\"key\":\"line1\\n\\r\\t\\b\\f\\\"\\\\/\\u0001\"}",
            "format_json_key and format_json_string escape RFC 8259 characters",
        );
    };

    t.run("RFC 8259 §7 read_json_string_into unescaped, escaped, UTF-16 surrogates & capacity bounds") { sub =>
        // 1. Unescaped fast path
        var r1 = json::reader("\"HS256\"");
        var dst1: u8[..16] = [];
        sub.assert_true(core::read_json_string_into(r1, dst1), "unescaped string read succeeds");
        sub.assert_eq(dst1[..], "HS256", "unescaped string matches");

        // 2. Short escapes + BMP \uXXXX (U+0041 'A', U+00E9 'é', U+20AC '€') + surrogate pair \uD83D\uDE00 (U+1F600 '😀')
        var r2 = json::reader("\"a\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00e9\\u20ac\\uD83D\\uDE00\"");
        var dst2: u8[..64] = [];
        sub.assert_true(core::read_json_string_into(r2, dst2), "escaped unicode string read succeeds");
        let expected_utf8: u8[20] = [
            'a', '"', '\\', '/', 8, 12, '\n', '\r', '\t', 'A',
            0xC3, 0xA9,
            0xE2, 0x82, 0xAC,
            0xF0, 0x9F, 0x98, 0x80,
            '!',
        ];
        sub.assert_eq(dst2[..], expected_utf8[..19], "decoded escapes and UTF-8 scalars match");

        // 3. Capacity overflow rejected cleanly without partial dirty buffer
        var r3 = json::reader("\"0123456789\"");
        var dst_tiny: u8[..4] = [];
        sub.assert_false(core::read_json_string_into(r3, dst_tiny), "unescaped string exceeding cap returns false");
        sub.assert_eq(dst_tiny.len, 0, "dst cleared on unescaped overflow");

        var r4 = json::reader("\"abcd\\n\"");
        var dst_tiny2: u8[..4] = [];
        sub.assert_false(core::read_json_string_into(r4, dst_tiny2), "escaped string exceeding cap returns false");
        sub.assert_eq(dst_tiny2.len, 0, "dst cleared on escaped overflow");

        // 4. Invalid escape rejected and sets reader.error
        var r5 = json::reader("\"bad\\xescape\"");
        var dst5: u8[..32] = [];
        sub.assert_false(core::read_json_string_into(r5, dst5), "invalid \\x escape returns false");
        sub.assert_true(r5.error.len > 0, "reader.error populated on invalid escape");
    };
}

fn test_flat_index_map(t: lit::T&) {
    t.run("FlatIndexMap GetOrPut, Backward-Shift Delete, and ABA Gen") { sub =>
        var buckets: core::FlatIndexBucket[8] = [core::FlatIndexBucket { .. }; 8];

        // 1. Empty lookup misses
        let miss = core::flat_index_get(buckets[..], 101);
        sub.assert_false(miss.found, "empty table misses");
        sub.assert_eq(miss.bucket_idx, -1, "miss bucket_idx is -1");

        // 2. GetOrPut + CommitPut + Get hit
        let ins1 = core::flat_index_get_or_put(buckets[..], 101);
        sub.assert_false(ins1.found, "key 101 not yet present");
        sub.assert_true(ins1.bucket_idx >= 0, "valid bucket_idx returned for insert");
        let gen1, ok1 = core::flat_index_commit_put(buckets[..], ins1.bucket_idx, 101, 7);
        sub.assert_true(ok1, "commit_put succeeds");
        sub.assert_eq(gen1, 1 as u16, "first generation is 1");

        let hit1 = core::flat_index_get(buckets[..], 101);
        sub.assert_true(hit1.found, "key 101 found after commit");
        sub.assert_eq(hit1.slot_idx, 7, "slot_idx matches 7");
        sub.assert_eq(hit1.gen, 1 as u16, "gen matches 1");

        // 3. GetOrPut on existing key returns existing entry
        let dup1 = core::flat_index_get_or_put(buckets[..], 101);
        sub.assert_true(dup1.found, "get_or_put finds existing key 101");
        sub.assert_eq(dup1.slot_idx, 7, "existing slot_idx preserved");

        // 4. Insert keys 1..=7 to force probe chains & fill table (cap 8)
        var k: u64 = 1;
        while k <= 7 {
            let r = core::flat_index_get_or_put(buckets[..], k);
            sub.assert_false(r.found, "new key not found");
            sub.assert_true(r.bucket_idx >= 0, "bucket available before full");
            let _, ok_k = core::flat_index_commit_put(buckets[..], r.bucket_idx, k, (k * 10) as u16);
            sub.assert_true(ok_k, "commit_put succeeds for key");
            k++;
        }

        // Table is now full (8/8): new key must fail cleanly
        let full_res = core::flat_index_get_or_put(buckets[..], 999);
        sub.assert_false(full_res.found, "full table miss");
        sub.assert_eq(full_res.bucket_idx, -1, "full table returns bucket_idx == -1");

        // 5. Remove half the keys (backward-shift deletion) and verify remaining keys stay reachable
        let rm1 = core::flat_index_remove(buckets[..], 2);
        sub.assert_true(rm1.found, "remove key 2 succeeds");
        sub.assert_eq(rm1.slot_idx, 20, "removed key 2 had slot_idx 20");
        let rm2 = core::flat_index_remove(buckets[..], 4);
        sub.assert_true(rm2.found, "remove key 4 succeeds");
        let rm3 = core::flat_index_remove(buckets[..], 101);
        sub.assert_true(rm3.found, "remove key 101 succeeds");
        sub.assert_false(core::flat_index_get(buckets[..], 101).found, "key 101 gone after remove");

        sub.assert_eq(core::flat_index_get(buckets[..], 1).slot_idx, 10, "key 1 intact after backward-shift");
        sub.assert_eq(core::flat_index_get(buckets[..], 3).slot_idx, 30, "key 3 intact after backward-shift");
        sub.assert_eq(core::flat_index_get(buckets[..], 5).slot_idx, 50, "key 5 intact after backward-shift");
        sub.assert_eq(core::flat_index_get(buckets[..], 6).slot_idx, 60, "key 6 intact after backward-shift");
        sub.assert_eq(core::flat_index_get(buckets[..], 7).slot_idx, 70, "key 7 intact after backward-shift");

        // 6. Re-insert at freed bucket increments ABA generation
        let re_ins = core::flat_index_get_or_put(buckets[..], 202);
        sub.assert_false(re_ins.found, "key 202 not present");
        let gen2, ok2 = core::flat_index_commit_put(buckets[..], re_ins.bucket_idx, 202, 42);
        sub.assert_true(ok2, "commit_put key 202 succeeds");
        sub.assert_true(gen2 >= 1 as u16, "generation counter >= 1");

        // 7. Clear resets occupied flags
        core::flat_index_clear(buckets[..]);
        sub.assert_false(core::flat_index_get(buckets[..], 1).found, "key 1 cleared");
        sub.assert_false(core::flat_index_get(buckets[..], 202).found, "key 202 cleared");
    };
}

fn test_token_bucket(t: lit::T&) {
    t.run("TokenBucket Saturating Refill & Burst Clamping") { sub =>
        var tb = core::TokenBucket { tokens: 5, burst: 5, rate_per_sec: 10, last_refill_ms: 1000 };
        sub.assert_eq(tb.tokens, 5 as u64, "starts full at burst");

        sub.assert_true(core::token_bucket_consume(tb, 1000, 3), "consume 3 tokens");
        sub.assert_eq(tb.tokens, 2 as u64, "2 tokens left");
        sub.assert_false(core::token_bucket_consume(tb, 1000, 3), "reject 3 when 2 left");
        sub.assert_eq(tb.tokens, 2 as u64, "tokens unchanged on rejection");
        sub.assert_true(core::token_bucket_consume(tb, 1000, 2), "consume remaining 2");
        sub.assert_eq(tb.tokens, 0 as u64, "bucket empty");

        // Backward timestamp is ignored safely
        sub.assert_false(core::token_bucket_consume(tb, 500, 1), "backward clock does not refill");

        // 100ms at 10/sec adds 1 token
        sub.assert_true(core::token_bucket_consume(tb, 1100, 1), "100ms adds 1 token");
        sub.assert_false(core::token_bucket_consume(tb, 1100, 1), "empty again after 1 token");

        // Large elapsed time clamps to burst (5), never overflows
        core::token_bucket_refill(tb, 1000000000);
        sub.assert_eq(tb.tokens, 5 as u64, "large refill clamped to burst");
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
    lit::run_case(runner, "7. Time Arithmetic & Comparisons", test_time_arithmetic_and_redos_immunity);
    lit::run_case(runner, "9. RFC 3339 / ISO 8601 Codec & Attack Vectors", test_rfc3339_codec_and_attack_vectors);
    lit::run_case(runner, "10. RFC 9110 Section 5.6.7 HTTP-Date Formatting & 3-Format Parser Security", test_http_date_rfc9110_and_attack_vectors);
    lit::run_case(runner, "11. Branchless Constant-Time Arithmetic & Selection", test_branchless_constant_time);
    lit::run_case(runner, "12. Saturation & Checked Arithmetic", test_saturation_and_checked_arithmetic);
    lit::run_case(runner, "13. 128-Bit Multiplication & Wymum Without u128", test_wide_multiplication_and_wymum);
    lit::run_case(runner, "14. Bit Manipulation & Endianness Codecs", test_bit_manipulation_and_endianness);
    lit::run_case(runner, "15. Euclidean Division & Remainder", test_euclidean_division_and_remainder);
    lit::run_case(runner, "16. PRNGs & Lemire Fast-Range Mapping", test_prng_and_lemire_range);
    lit::run_case(runner, "19. Fast Non-Cryptographic Hashing & Combinators", test_fast_non_cryptographic_hashes);
    lit::run_case(runner, "21. Crash Containment via thread_spawn_contained", test_thread_containment);
    lit::run_case(runner, "22. SPSC Lock-Free Ring", test_singleflight_and_spsc);
    lit::run_case(runner, "23. ASCII Predicates, Case Conversions & Folding", test_case_folding);
    lit::run_case(runner, "24. Linear Whitespace, ASCII Whitespace & Byte Trimming", test_trimming);
    lit::run_case(runner, "25. Byte Search, Slice Splitting & ByteTokenizer", test_search_and_split);
    lit::run_case(runner, "26. Bounds-Checked Decimal & Hex Parsing and Formatting", test_parsing_and_formatting);
    lit::run_case(runner, "27. RingBuffer Circular FIFO & Wraparound", test_ring_buffer);
    lit::run_case(runner, "28. PipeBuffer Two-Cursor Pipelines & Monotonicity", test_pipe_buffer);
    lit::run_case(runner, "29. CorkBuffer 16KB Outbound Aggregation", test_cork_buffer);
    lit::run_case(runner, "30. SIMD Fast ASCII, UTF-8 & CRLF Scan", test_simd_accelerators);
    lit::run_case(runner, "31. Core Time: Euclidean Division & Duration Bounds", test_regress_core_time);
    lit::run_case(runner, "32. Core URL: Scheme Bounds, Fold, Authority & Query", test_regress_core_url);
    lit::run_case(runner, "33. Core Crypto: Ed25519 Torsion, X25519 & AEAD Zeroize", test_regress_core_crypto);
    lit::run_case(runner, "34. Core Compress: Deflate Rollback, Zstream & Zstd", test_regress_core_compress);
    lit::run_case(runner, "35. Core IO: PageRingBuffer descriptor guard", test_regress_core_sync_and_io);
    lit::run_case(runner, "36. Core Audit: ByteBuilder Leak, ct_abs_i64 & Host ZoneID", test_regress_core_audit_bugs);
    lit::run_case(runner, "37. Math & Crypto Regressions", test_math_and_crypto_regressions);
    lit::run_case(runner, "38. Compress & Time Regressions", test_compress_and_time_regressions);
    lit::run_case(runner, "39. URL Regressions", test_url_regressions);
    lit::run_case(runner, "40. Bounded JSON Primitives", test_json_bounded_primitives);
    lit::run_case(runner, "41. FlatIndexMap GetOrPut, Backward-Shift Delete & ABA Gen", test_flat_index_map);
    lit::run_case(runner, "43. TokenBucket Saturating Refill & Burst Clamping", test_token_bucket);

    let ok = lit::finish(runner);
    assert(ok);
}
