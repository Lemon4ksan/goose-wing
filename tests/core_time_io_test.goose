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
            sub.assert_eq(core::weekday_number(wd), w);
            sub.assert_gt(core::weekday_name(wd).len, 2);
            sub.assert_gt(core::weekday_short_name(wd).len, 2);
        }
        sub.assert_eq(core::weekday_number(core::weekday_from_number(99)), 1);

        let leap_t = core::date(2024, core::Month.February, 15, 10, 20, 30, 500000000);
        let nonleap_t = core::date(2025, core::Month.February, 15, 10, 20, 30, 500000000);
        sub.assert_true(core::is_leap_year(leap_t));
        sub.assert_false(core::is_leap_year(nonleap_t));
        sub.assert_eq(core::days_in_year(leap_t), 366);
        sub.assert_eq(core::days_in_year(nonleap_t), 365);
        sub.assert_eq(core::days_in_month(leap_t), 29);
        sub.assert_eq(core::days_in_month(nonleap_t), 28);
        sub.assert_eq(leap_t.month(), core::Month.February);
        let ch, cm, cs = leap_t.clock();
        sub.assert_true(ch == 10 && cm == 20 && cs == 30);

        let zt = core::Time { .. };
        sub.assert_true(core::is_zero(zt));
        sub.assert_eq(core::tz_offset(core::in_offset(leap_t, -18000)), -18000);
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

        // truncate / round (subsecond divisors, negative times, general nanos, non-positive)
        let neg_t = core::unix(-5, 600000000);
        sub.assert_eq(core::truncate(leap_t, core::nanos(0)), leap_t);
        sub.assert_eq(core::truncate(leap_t, core::millis(250)).nsec, 500000000);
        sub.assert_eq(core::round(leap_t, core::nanos(0)), leap_t);
        let _ = core::round(neg_t, core::millis(500));
        let _ = core::round(leap_t, core::millis(700));
        let _ = core::round(neg_t, core::millis(700));
        let _ = core::round(leap_t, core::secs(3));
        let _ = core::since(zt);
        let _ = core::until(zt);
    };
}

fn test_time_format_dur_sim_wheel(t: lit::T&) {
    t.run("RFC3339/HTTP date format & parse error paths + Duration helpers") { sub =>
        let t_neg_tz = core::in_offset(core::unix(1700000000, 123000000), -18000);
        let t_pos_tz = core::in_offset(core::unix(1700000000, 0), 19800);
        var buf: u8[..128] = [];
        core::format_rfc3339_nano(buf, t_neg_tz);
        sub.assert_true(buf[..].contains_byte('-'));
        buf.clear();
        core::format_rfc3339_nano(buf, t_pos_tz);
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

        // Duration aliases, round up/exact, unicode us/μs, clamping min negative
        let d_ns = core::nanoseconds(500);
        let d_us = core::microseconds(2);
        let d_ms = core::milliseconds(3);
        let d_s = core::seconds(4);
        let d_m = core::minutes(1);
        sub.assert_eq(core::nanoseconds(d_ns), 500);
        sub.assert_eq(core::microseconds(d_us), 2);
        sub.assert_eq(core::milliseconds(d_ms), 3);
        sub.assert_gt(core::seconds(d_s), 3.9);
        sub.assert_gt(core::minutes(d_m), 0.9);
        sub.assert_gt(core::hours(core::secs(3600)), 0.9);
        sub.assert_eq(core::add(d_ms, d_ms), core::millis(6));
        sub.assert_eq(core::sub(d_ms, core::millis(1)), core::millis(2));
        sub.assert_eq(core::abs(core::nanos(-42)), core::nanos(42));
        sub.assert_eq(core::round(core::nanos(2), core::nanos(4)), core::nanos(4));
        sub.assert_eq(core::round(core::nanos(4), core::nanos(4)), core::nanos(4));

        let du_mu, ok_mu = core::parse_duration("5us");
        let du_gr, ok_gr = core::parse_duration("5μs");
        let du_min, ok_min = core::parse_duration("-2562047h47m16s854ms775us808ns");
        sub.assert_true(ok_mu && ok_gr && ok_min, "parse_duration min/us");
        sub.assert_eq(du_mu.nanos, 5000);
        sub.assert_eq(du_gr.nanos, 5000);
        sub.assert_eq(du_min.nanos, core::DURATION_MIN_NANOS);
        let _, ok_bd1 = core::parse_duration("1badunit");
        let _, ok_bd2 = core::parse_duration("abc.5s");
        let _, ok_bd3 = core::parse_duration("1.xxs");
        let _, ok_bd4 = core::parse_duration("999999999999h");
        sub.assert_false(ok_bd1 || ok_bd2 || ok_bd3 || ok_bd4);
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
    t.run("GuardedArena, MmapFile, PinnedBuffer & PageRing error/edge paths") { sub =>
        let _, ok_z = core::guarded_arena_init(0, 0);
        sub.assert_false(ok_z);
        var bad_a = core::GuardedArena {};
        var b8: u8[8] = [0; 8];
        let _, ok_gw = core::guarded_arena_write(bad_a, "hi");
        let _, ok_gr = core::guarded_arena_read(bad_a, 0, b8[..]);
        sub.assert_false(ok_gw || ok_gr || core::guarded_arena_reset(bad_a));
        core::guarded_arena_close(bad_a);

        var ok_ar, a_init = core::guarded_arena_init(4096, 0);
        if a_init {
            defer core::guarded_arena_close(ok_ar);
            let _ = core::guarded_arena_write(ok_ar, "hello");
            let _, _ = core::guarded_arena_read(ok_ar, 0, b8[..2]);
            let _ = core::guarded_arena_available(ok_ar);
            let _ = core::guarded_arena_reset(ok_ar);
        }

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

        let _, ok_pb0 = core::pinned_buffer_init(0);
        sub.assert_false(ok_pb0);
        var pb, ok_pb = core::pinned_buffer_init(4096);
        if ok_pb {
            defer core::pinned_buffer_close(pb);
            let _, ok_pw = core::pinned_buffer_write(pb, 0, "abc");
            let _, ok_pr = core::pinned_buffer_read(pb, 0, b8[..3]);
            let _, ok_pw_oob = core::pinned_buffer_write(pb, 4096, "abc");
            let _, ok_pr_oob = core::pinned_buffer_read(pb, 4096, b8[..3]);
            sub.assert_true(ok_pw && ok_pr && !ok_pw_oob && !ok_pr_oob);
        }

        var pr = core::PageRingBuffer {};
        sub.assert_false(core::page_ring_init(pr, 0));
        sub.assert_eq(core::page_ring_available(pr), 0);
        let _, e_pw = core::page_ring_write(pr, "a");
        let _, e_pr = core::page_ring_read(pr, b8[..]);
        sub.assert_true(e_pw == core::IoError.Closed && e_pr == core::IoError.Closed);
        sub.assert_eq(core::page_ring_peek(pr, b8[..]), 0);
        sub.assert_eq(core::page_ring_discard(pr, 4), 0);
        sub.assert_eq(core::page_ring_recv(pr, -1), -1);
        sub.assert_eq(core::page_ring_find_crlf(pr), -1);
        sub.assert_eq(core::page_ring_find_crlfcrlf(pr), -1);
        if core::page_ring_init(pr, 4096) {
            defer core::page_ring_close(pr);
            let _, e_empty_r = core::page_ring_read(pr, b8[..]);
            let _, e_zero_w = core::page_ring_write(pr, "");
            sub.assert_true(e_empty_r == core::IoError.Eof && e_zero_w == core::IoError.None);
            let wn, e_w = core::page_ring_write(pr, "hello\r\n\r\n");
            sub.assert_true(wn == 9 && e_w == core::IoError.None);
            sub.assert_eq(core::page_ring_find_crlf(pr), 5);
            sub.assert_eq(core::page_ring_find_crlfcrlf(pr), 5);
            sub.assert_eq(core::page_ring_peek(pr, b8[..5]), 5);
            sub.assert_eq(core::page_ring_discard(pr, 5), 5);
            let _, _ = core::page_ring_read(pr, b8[..4]);
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

        // IoVecArray compact, push overflow, consume, copy_chunk
        var vec = core::new_iovec_array();
        sub.assert_eq(core::iovec_total_bytes(vec), 0);
        sub.assert_bytes_eq(core::iovec_get(vec, -1), "");
        sub.assert_eq(core::iovec_consume(vec, 0), 0);
        sub.assert_true(core::iovec_push(vec, "hello"));
        sub.assert_true(core::iovec_push(vec, "world"));
        sub.assert_eq(core::iovec_consume(vec, 2), 2);
        core::iovec_compact(vec);
        sub.assert_eq(core::iovec_total_bytes(vec), 8);
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
