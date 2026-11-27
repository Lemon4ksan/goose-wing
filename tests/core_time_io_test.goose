// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: core/time and core/io deep boundary & error coverage.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_time_core_and_calendar(t: lit::T&) {
    t.run("Calendar month/weekday tables and Time rounding/arithmetic boundaries") { sub =>
        for m in 1..13 {
            let mo = core::month_from_number(m);
            sub.assert_eq(core::month_number(mo), m);
            sub.assert_gt(core::month_name(mo).len, 2);
            sub.assert_gt(core::month_short_name(mo).len, 2);
        }
        sub.assert_eq(core::month_number(core::month_from_number(0)), 12);
        sub.assert_eq(core::month_number(core::month_from_number(99)), 3);

        for w in 0..7 {
            let wd = core::weekday_from_number(w);
            sub.assert_gt(core::weekday_name(wd).len, 2);
            sub.assert_gt(core::weekday_short_name(wd).len, 2);
        }

        let leap_t = core::date(2024, core::Month.February, 15, 10, 20, 30, 500000000);
        let nonleap_t = core::date(2025, core::Month.February, 15, 10, 20, 30, 500000000);
        sub.assert_true(core::is_leap_year(leap_t));
        sub.assert_false(core::is_leap_year(nonleap_t));
        sub.assert_eq(core::days_in_month(leap_t), 29);
        sub.assert_eq(core::days_in_month(nonleap_t), 28);
        sub.assert_eq(leap_t.month(), core::Month.February);
        let ch, cm, cs = leap_t.clock();
        sub.assert_true(ch == 10 && cm == 20 && cs == 30);

        let zt = core::Time { .. };
        sub.assert_true(core::is_zero(zt));
        let t_off = core::date(2024, core::Month.February, 15, 10, 20, 30, 500000000, -18000);
        sub.assert_eq(core::tz_offset(t_off), -18000);
        sub.assert_eq(core::unix(core::unix_milli(1234)), 1);
        sub.assert_eq(core::unix(core::unix_micro(2000000)), 2);

        // Nsec carry/borrow in add/sub and large wall_sec sub clamping
        let t_pos = core::unix(5, 800000000);
        let t_add = core::add(t_pos, core::millis(400));
        sub.assert_eq(core::unix(t_add), 6);
        let t_sub_b = core::sub(t_pos, core::millis(900));
        sub.assert_eq(core::unix(t_sub_b), 4);
        let huge_pos = core::unix(9000000000, 0);
        let huge_neg = core::unix(-9000000000, 0);
        sub.assert_eq(core::sub(huge_pos, huge_neg).nanos, core::DURATION_MAX_NANOS);
        sub.assert_eq(core::sub(huge_neg, huge_pos).nanos, core::DURATION_MIN_NANOS);

        let _ = core::since(zt);
    };
}

fn test_time_format_dur_sim_wheel(t: lit::T&) {
    t.run("RFC3339/HTTP date format & parse error paths + Duration helpers") { sub =>
        let t_neg_tz = core::date(2023, 11, 14, 17, 13, 20, 123000000, -18000);
        let t_pos_tz = core::date(2023, 11, 15, 3, 43, 20, 0, 19800);
        var buf: u8[..128] = [];
        core::format_rfc3339(buf, t_neg_tz);
        sub.assert_true(buf[..].contains_byte('-'));
        buf.clear();
        core::format_rfc3339(buf, t_pos_tz);
        sub.assert_true(buf[..].contains_byte('+'));
        buf.clear();
        core::format(buf, t_neg_tz);
        core::format(buf, core::Month.January);
        core::format(buf, core::Weekday.Monday);
        sub.assert_gt(buf.len, 10);

        let bad_rfc: const u8[:][6] = [
            "2026-01",
            "2026/01/01T00:00:00Z",
            "2026-01-01T00:00:00Q",
            "2026-01-01T00:00:00+5",
            "0000-01-01T00:00:00Z",
            "2026-01-01T12:00:60Z",
        ];
        for r in bad_rfc {
            let _, ok = core::parse_rfc3339(r);
            sub.assert_false(ok, r);
        }

        // HTTP dates: RFC 1123 all months/weekdays, RFC 850 (both century pivots), asctime, bad inputs
        let good_http: const u8[:][5] = [
            "Mon, 02 Jan 2023 03:04:05 GMT",
            "Fri, 03 Mar 2023 03:04:05 GMT",
            "Sat, 04 May 2024 03:04:05 GMT",
            "Tuesday, 15-Jun-99 12:00:00 GMT",
            "Thu Aug 15 08:09:10 2024",
        ];
        for h in good_http {
            let _, ok = core::parse_http_date(h);
            sub.assert_true(ok, h);
        }
        let _, ok_jul = core::parse_http_date("Tue, 11 Jul 2023 00:00:00 GMT");
        let _, ok_sep = core::parse_http_date("Thu, 07 Sep 2023 00:00:00 GMT");
        let _, ok_dec = core::parse_http_date("Fri, 01 Dec 2023 00:00:00 GMT");
        sub.assert_true(ok_jul && ok_sep && ok_dec, "jul/sep/dec");

        let bad_http: const u8[:][6] = [
            "Monday, 15-Jun-23 12:00:00 GMT",
            "Thu Foo 15 08:09:10 2024",
            "Mon, 02-Jan-23 03:04:05 GMT",
            "Mon, 02 Jan 2023 99:04:05 GMT",
            "Tue, 02 Jan 2023 03:04:05 GMT",
            "Tuesday, xx-Jun-99 12:00:00 GMT",
        ];
        for bh in bad_http {
            let _, ok = core::parse_http_date(bh);
            sub.assert_false(ok, bh);
        }

        // Duration helpers, round up/exact
        let d_ns = core::nanos(500);
        let d_us = core::micros(2);
        let d_ms = core::millis(3);
        let d_s = core::secs(4);
        let d_m = core::mins(1);
        sub.assert_eq(core::as_nanos(d_ns), 500);
        sub.assert_eq(core::as_micros(d_us), 2);
        sub.assert_eq(core::as_millis(d_ms), 3);
        sub.assert_gt(core::as_secs_f64(d_s), 3.9);
        sub.assert_eq(core::as_secs(d_m), 60);
        sub.assert_eq(core::as_secs(core::hours(1)), 3600);
        sub.assert_eq(d_ms + d_ms, core::millis(6));
        sub.assert_eq(d_ms - core::millis(1), core::millis(2));
        sub.assert_eq(core::abs(core::nanos(-42)), core::nanos(42));
        sub.assert_eq(core::round(core::nanos(2), core::nanos(4)), core::nanos(4));
        sub.assert_eq(core::round(core::nanos(4), core::nanos(4)), core::nanos(4));
    };

    t.run("Clock sleep<=0, SimClock/SimRng, TickTimer, TokenBucket") { sub =>
        core::sleep(core::nanos(0));
        core::sleep(core::nanos(1));

        var tmp: u8[8] = [0; 8];
        core::sim_rng_disable();
        sub.assert_false(core::sim_rng_fill(tmp[..]));
        core::sim_clock_enable(1000);
        defer core::sim_clock_disable();
        let adv = core::sim_clock_advance(500);
        sub.assert_eq(adv, 1500);

        var wheel = core::TickTimerWheel { current_tick: 60, idle_timeout_sec: 10 };
        let arm_def = core::tick_timer_arm(wheel, 0);
        let arm_ex = core::tick_timer_arm(wheel, 5);
        sub.assert_true(arm_def != arm_ex);
        let _ = core::tick_timer_advance(wheel, 128);
        sub.assert_true(core::tick_timer_is_expired(wheel, arm_def));

        var tb = core::TokenBucket { tokens: 0, burst: 100, rate_per_sec: 10000000000, last_refill_ms: 0 };
        sub.assert_true(core::token_bucket_consume(tb, 1000000000000 as u64, 1));
    };
}

fn test_io_all_buffers_and_guards(t: lit::T&) {
    t.run("MmapFile & PageRing error/edge paths") { sub =>
        var b8: u8[8] = [0; 8];
        let _, ok_m1 = core::mmap_file_open("");
        let _, ok_m2 = core::mmap_file_open("missing_nonexistent_file_xyz_12345.bin");
        sub.assert_false(ok_m1 || ok_m2);
        var mf_ok, ok_mf = core::mmap_file_open("LICENSE");
        if ok_mf {
            defer core::mmap_file_close(mf_ok);
            let _, ok_oob = core::mmap_file_read(mf_ok, mf_ok.size + 10, b8[..]);
            sub.assert_false(ok_oob);
            let _, ok_bad_fd = core::mmap_file_send(mf_ok, 0, 8 as u32, -1);
            sub.assert_false(ok_bad_fd);
            let _, ok_big_s = core::mmap_file_send(mf_ok, mf_ok.size + 1, 8 as u32, 0);
            sub.assert_false(ok_big_s);
        }

        var pr = core::PageRingBuffer {};
        sub.assert_false(core::page_ring_init(pr, 0));
        sub.assert_eq(core::page_ring_available(pr), 0);
        sub.assert_eq(core::page_ring_peek(pr, b8[..]), 0);
        sub.assert_eq(core::page_ring_discard(pr, 4), 0);
        sub.assert_eq(core::page_ring_recv(pr, -1), -1);
        if core::page_ring_init(pr, 4096) {
            defer core::page_ring_close(pr);
            sub.assert_gt(core::page_ring_available(pr), 0);
            sub.assert_eq(core::page_ring_peek(pr, b8[..5]), 0);
            sub.assert_eq(core::page_ring_discard(pr, 5), 0);
        }
    };

    t.run("Cursor, BitStream, Builder, IoVec, Pipe, Cork, Ring, Reactor, Types") { sub =>
        // ByteCursor & BitStreamReader & ByteBuilder error guards
        var cur = core::cursor_from("abc");
        sub.assert_eq(core::cursor_len(cur), 3);
        let _, ok_u32 = core::read_u32(cur);
        var cur_e = core::cursor_from("");
        var cur_a = core::cursor_from("a");
        let _, ok_u8p = core::read_u8_prefixed(cur_e);
        let _, ok_u24p = core::read_u24_prefixed(cur_a);
        sub.assert_false(ok_u32 || ok_u8p || ok_u24p);

        var br = core::make_bit_reader("A");
        let _, ok_bits_bad = core::read_bits(br, 60);
        let _, ok_bits_eof = core::read_bits(br, 16);
        sub.assert_false(ok_bits_bad || ok_bits_eof);

        var bld = core::ByteBuilder {};
        sub.assert_false(core::finish_u8_prefix(bld));
        sub.assert_false(core::finish_u16_prefix(bld));
        sub.assert_false(core::finish_u24_prefix(bld));
        for _ in 16 { let _ = core::start_u8_prefix(bld); }
        sub.assert_false(core::start_u8_prefix(bld));
        sub.assert_false(core::start_u16_prefix(bld));
        sub.assert_false(core::start_u24_prefix(bld));

        // IoVecArray compact, push overflow, consume
        var vec = core::new_iovec_array();
        sub.assert_eq(vec.total_bytes, 0);
        sub.assert_bytes_eq(core::iovec_get(vec, -1), "");
        sub.assert_eq(core::iovec_consume(vec, 0), 0);
        sub.assert_true(core::iovec_push(vec, "hello"));
        sub.assert_true(core::iovec_push(vec, "world"));
        sub.assert_eq(core::iovec_consume(vec, 2), 2);
        core::iovec_compact(vec);
        sub.assert_eq(vec.total_bytes, 8);
        for _ in 16 { let _ = core::iovec_push(vec, "x"); }
        sub.assert_false(core::iovec_push(vec, "overflow"));

        // PipeBuffer compact, peek, errors, get_write_span
        var pipe = core::PipeBuffer {};
        var p8: u8[8] = [0; 8];
        let _, pr_empty = core::read(pipe, p8[..]);
        sub.assert_true(pr_empty == core::IoError.None);
        sub.assert_eq(core::peek(pipe, p8[..]), 0);
        let _, pw0 = core::write(pipe, "");
        let _, pw1 = core::write(pipe, "abcdef");
        sub.assert_true(pw0 == core::IoError.None && pw1 == core::IoError.None);
        sub.assert_eq(core::peek(pipe, p8[..3]), 3);
        let pa_err1 = core::advance_to(pipe, -1, 0);
        let pa_err2 = core::advance_to(pipe, 99, 99);
        let pa_err3 = core::advance_to(pipe, 4, 2);
        sub.assert_true(pa_err1 != core::IoError.None && pa_err2 != core::IoError.None && pa_err3 != core::IoError.None);
        let _ = core::advance_to(pipe, 3, 4);
        core::compact_pipe(pipe);
        let cw_bad = core::commit_write(pipe, -1);
        let _, gws_bad = core::get_write_span(pipe, 0);
        sub.assert_true(cw_bad != core::IoError.None && gws_bad != core::IoError.None);

        // CorkBuffer resize, consume, u8/u24/u32 errors
        var cork = core::new_cork_buffer();
        sub.assert_eq(core::cork_pending(cork), 0);
        core::cork_consume(cork, 0);
        cork.resize(8);
        sub.assert_eq(core::cork_pending(cork), 8);
        cork.clear();
        sub.assert_true(core::cork_write_exact(cork, "ok") == core::IoError.None);
        sub.assert_true(core::cork_write_u24_be(cork, 0x1000000) == core::IoError.InvalidArgument);
        sub.assert_true(core::cork_write_u32_be(cork, 1) == core::IoError.None);
        sub.assert_true(core::cork_write_u8(cork, 1) == core::IoError.None);

        // RingBuffer realign, full write, empty peek/discard/slices
        var rb = core::new_ring_buffer();
        sub.assert_eq(rb.peek(p8[..]), 0);
        sub.assert_eq(rb.discard(0), 0);
        let rs1, rs2 = rb.read_slices();
        sub.assert_true(rs1.len == 0 && rs2.len == 0);
        let _, _ = rb.write("abcdef");
        let _ = rb.discard(2);
        core::realign_ring(rb);
        let ws1, ws2 = rb.write_slices();
        sub.assert_true(ws1.len > 0 && ws2.len >= 0);

        // Types & Reactor guards
        var mp = MockPoller {};
        var evs: core::PollReadyEvent[..64] = [];
        sub.assert_eq(core::interest_to_poll_flags(core::PollInterest.None), core::POLL_NONE);
        sub.assert_false(core::reactor_register(mp, -1, 1 as u64, core::PollInterest.Read));
        sub.assert_false(core::reactor_modify(mp, -1, 1 as u64, core::PollInterest.Read));
        sub.assert_false(core::reactor_deregister(mp, -1));
        sub.assert_false(core::reactor_add_timer(mp, 0 as u64, 10 as u64, 1 as u64));
        sub.assert_false(core::reactor_cancel_timer(mp, 0 as u64));
        sub.assert_eq(core::reactor_poll(mp, -2, 0 as u64, evs), 0);
        let _ = core::reactor_poll(mp, 0, 0 as u64, evs);
    };
}

struct MockPoller {
    calls: i32 = 0,
}

fn ::register_socket(p: MockPoller&, _fd: i32, _tag: u64, _i: core::PollInterest, _t: core::PollTrigger) -> bool {
    p.calls += 1;
    return true;
}

fn ::modify_socket(p: MockPoller&, _fd: i32, _tag: u64, _i: core::PollInterest, _t: core::PollTrigger) -> bool {
    p.calls += 1;
    return true;
}

fn ::deregister_socket(p: MockPoller&, _fd: i32) -> bool { p.calls += 1; return true; }

fn ::add_timer(p: MockPoller&, _tid: u64, _d: u64, _t: u64, _per: bool, _n: u64) -> bool {
    p.calls += 1;
    return true;
}

fn ::cancel_timer(p: MockPoller&, _tid: u64) -> bool { p.calls += 1; return true; }

fn ::poll_events(p: MockPoller&, _to: i64, _now: u64, _out: core::PollReadyEvent[..64]&) -> i32 {
    p.calls += 1;
    return 0;
}

fn main() {
    let runner = lit::new_runner("Core Time and IO Verification Suite");
    lit::run_case(runner, "1. Calendar & Time Arithmetic", test_time_core_and_calendar);
    lit::run_case(runner, "2. Time Formats, Duration, Sim & Timers", test_time_format_dur_sim_wheel);
    lit::run_case(runner, "3. Core IO Buffers, Cursors & Reactor Guards", test_io_all_buffers_and_guards);
    assert(lit::finish(runner));
}
