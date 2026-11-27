// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deep Verification Suite: core root utilities, core/io contracts, tick timer, and extra crypto error paths.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

struct MockIo {
    tx_limit: i32  = 64,
    next_rc:  i32  = -2,
    closed:   bool = false,
}

struct MockHost {
    rx_paused: bool = false,
    shutdown:  bool = false,
}

fn ::link_listen(_h: MockHost&, _a: core::ConnectAddr, owner: u16, _tag: u64, _bl: i32) -> core::IoLink, core::IoError {
    return core::make_io_link(owner, 1, 5), core::IoError.None;
}
fn ::link_connect(_h: MockHost&, _a: core::ConnectAddr, owner: u16, _tag: u64) -> core::IoLink, core::ConnectStatus {
    return core::make_io_link(owner, 2, 9), core::ConnectStatus.Connected;
}
fn ::link_send(_h: MockHost&, _l: core::IoLink, data: const u8[:]) -> i32, core::IoError {
    return data.len as i32, core::IoError.None;
}
fn ::link_set_rx_paused(h: MockHost&, _l: core::IoLink, p: bool) -> bool { h.rx_paused = p; return true; }
fn ::link_shutdown_write(h: MockHost&, _l: core::IoLink) -> bool { h.shutdown = true; return true; }
fn ::link_close(_h: MockHost&, _l: core::IoLink) -> bool { return true; }
fn ::link_add_timer(_h: MockHost&, _id: u64, _d: u64, _o: u16, _t: u64, _p: bool, _n: u64) -> bool { return true; }
fn ::link_cancel_timer(_h: MockHost&, _id: u64) -> bool { return true; }
fn ::link_wake(_h: MockHost&, _tok: core::WakeToken) -> bool { return true; }
fn ::link_poll_dispatch(
    h:    MockHost&,
    drv:  core::IoDriverChain<core::NoOpIoDriver, core::NoOpIoDriver>&,
    _tm:  i64,
    _now: u64,
) -> i32 {
    let ev = core::LinkEvent {};
    core::on_link_event(drv.first, h, ev);
    core::on_link_event(drv.next, h, ev);
    return 1;
}

fn test_root_and_ufcs(t: lit::T&) {
    t.run("Secret, Opt, UFCS bridges, tick timer & sim edges") { sub =>
        var sec = core::Secret<u8[..16]> {};
        let _ = sec.val.try_append("top-secret");
        sub.assert_true(core::ct_eq(sec, "top-secret"));
        core::zeroize(sec);
        sub.assert_eq(sec.val.len, 0);

        let ov = core::opt_some(42 as i64);
        sub.assert_true(ov.present && ov.value == 42);

        // UFCS over trimmed/split/dyn vec/compact
        sub.assert_bytes_eq("xxabxx".trim_byte('x'), "ab");
        sub.assert_eq("a;\"b;c\";d".find_unquoted_byte(';'), 1);
        let sq_l, sq_r, sq_ok = "a;\"b;c\";d".split_once_unquoted_byte(';');
        sub.assert_true(sq_ok && sq_l == "a" && sq_r == "\"b;c\";d");

        var dyn: u8[>..] = [];
        sub.assert_true(dyn.try_push(65 as u8) && dyn.try_push(66 as i64));
        sub.assert_false(dyn.try_push(300 as i64));
        sub.assert_true(dyn.try_append("CD"));
        dyn.compact_wire_buffer(0);
        dyn.compact_wire_buffer(2);
        sub.assert_bytes_eq(dyn[..], "CD");
        dyn.compact_wire_buffer(99);
        sub.assert_eq(dyn.len, 0);
        sub.assert_true(dyn.try_set("EF"));
        sub.assert_bytes_eq(dyn[..], "EF");

        var qv: u8[..16] = [];
        sub.assert_true("k=v&f".get_query_param_fast("k", qv) == core::QueryParamMatch.Value);
        sub.assert_true("k=v&f".has_query_param_fast("f"));

        var m64: u64 = 0;
        m64 |= 0x0F as u64;
        sub.assert_true((m64 & (0x01 as u64)) != 0 && (m64 & (0x0F as u64)) == (0x0F as u64));
        m64 &= ~(0x02 as u64);
        sub.assert_false((m64 & (0x02 as u64)) != 0);

        // TickTimerWheel + sim clock/rng edges
        var wheel = core::TickTimerWheel { idle_timeout_sec: 10, .. };
        let s1 = core::tick_timer_arm(wheel, 0);
        let s2 = core::tick_timer_arm(wheel, 250);
        let dis = core::tick_timer_disarm();
        sub.assert_false(core::tick_timer_is_expired(wheel, dis));
        let _ = core::tick_timer_advance(wheel, 12);
        sub.assert_true(core::tick_timer_is_expired(wheel, s1));
        sub.assert_false(core::tick_timer_is_expired(wheel, s2));
        let _ = core::tick_timer_advance(wheel, 300);
        sub.assert_true(core::tick_timer_is_expired(wheel, s2));

        core::sim_rng_enable(77);
        sub.assert_true(core::sim_entropy_u64() != 0);
        core::sim_rng_disable();
        let _ = core::sim_entropy_u64();
        let _ = core::sim_clock_advance(-5);
    };
}

fn test_io_cursor_vec_pipe_cork_ring(t: lit::T&) {
    t.run("ByteCursor, BitStreamReader, ByteBuilder, IoVec, Pipe, Cork, Ring") { sub =>
        // ByteCursor & ByteBuilder & BitStreamReader
        let wire: u8[8] = [0x01, 0x02, 0x00, 0x01, 0x02, 0x03, 0xA5, 0x99];
        var c = core::cursor_from(wire[..]);
        sub.assert_eq(core::cursor_len(c), 8);
        var b1:   u8  = 0;
        var u16v: u16 = 0;
        var u24v: u32 = 0;
        sub.assert_true(core::get_u8(c, b1) && b1 == 0x01);
        sub.assert_true(core::get_u24(c, u24v) && u24v == 0x020001);
        sub.assert_true(core::get_u16(c, u16v) && u16v == 0x0203);
        var last_b: u8 = 0;
        sub.assert_true(core::get_last_u8(c, last_b) && last_b == 0x99);
        var u32c = core::cursor_from(wire[..3]);
        var u32v: u32 = 0;
        sub.assert_false(core::get_u32(u32c, u32v));
        var empty_c = core::cursor_from(wire[..0]);
        sub.assert_false(core::get_u16(empty_c, u16v));

        let framed: u8[10] = [0x02, 'A', 'B', 0x00, 0x02, 'C', 'D', 0x00, 0x00, 0x02];
        var fc = core::cursor_from(framed[..]);
        var sub_c = core::cursor_from(framed[..0]);
        sub.assert_true(core::get_u8_length_prefixed(fc, sub_c) && sub_c.buf == "AB");
        sub.assert_true(core::get_u16_length_prefixed(fc, sub_c) && sub_c.buf == "CD");
        sub.assert_false(core::get_u24_length_prefixed(fc, sub_c));

        let trunc_raw: u8[2] = [0x05, 'x'];
        var trunc_c = core::cursor_from(trunc_raw[..]);
        let _, ok_ru8 = core::read_u8_sub_cursor(trunc_c);
        sub.assert_false(ok_ru8);
        let t16_raw: u8[3] = [0x00, 0x09, 'x'];
        var t16_c = core::cursor_from(t16_raw[..]);
        let _, ok_rs16 = core::read_u16_prefixed(t16_c);
        let _, ok_ru16 = core::read_u16_sub_cursor(t16_c);
        sub.assert_false(ok_rs16 || ok_ru16);
        let t24_raw: u8[4] = [0x00, 0x00, 0x09, 'x'];
        var t24_c = core::cursor_from(t24_raw[..]);
        let _, ok_rs24 = core::read_u24_prefixed(t24_c);
        let _, ok_ru24 = core::read_u24_sub_cursor(t24_c);
        sub.assert_false(ok_rs24 || ok_ru24);
        let _, ok_rb = core::read_bytes(trunc_c, -1);
        sub.assert_false(ok_rb);

        let br_raw: u8[2] = [0xA5, 0x5A];
        var br = core::make_bit_reader(br_raw[..]);
        let bits4, ok_b4 = core::read_bits(br, 4);
        let bits8, ok_b8 = core::read_bits(br, 8);
        let _, ok_b_over = core::read_bits(br, 16);
        let _, ok_b_neg = core::read_bits(br, 99);
        sub.assert_true(ok_b4 && bits4 == 0x0A && ok_b8 && bits8 == 0x55);
        sub.assert_false(ok_b_over || ok_b_neg);

        var bb = core::builder_init();
        sub.assert_false(core::finish_u8_prefix(bb));
        sub.assert_false(core::finish_u16_prefix(bb));
        sub.assert_false(core::finish_u24_prefix(bb));
        sub.assert_true(core::start_u8_prefix(bb));
        core::put_bytes(bb, "hi");
        sub.assert_true(core::finish_u8_prefix(bb));
        sub.assert_true(core::start_u16_prefix(bb));
        core::put_u32(bb, 0x01020304);
        sub.assert_true(core::finish_u16_prefix(bb));
        sub.assert_true(core::start_u24_prefix(bb));
        core::put_u24(bb, 0x112233);
        sub.assert_true(core::finish_u24_prefix(bb));
        sub.assert_gt(bb.buf.len, 8);

        // IoVecArray: push, compact, consume
        var iov = core::new_iovec_array();
        sub.assert_true(core::iovec_is_empty(iov));
        for i in 16 { sub.assert_true(core::iovec_push(iov, "ab")); }
        sub.assert_false(core::iovec_push(iov, "full"));
        sub.assert_eq(core::iovec_consume(iov, 3), 3);
        sub.assert_true(core::iovec_push(iov, "xy"));
        sub.assert_eq(iov.total_bytes, 31);
        sub.assert_bytes_eq(core::iovec_get(iov, 0), "b");
        sub.assert_bytes_eq(core::iovec_get(iov, -1), "");
        iov = core::new_iovec_array();
        sub.assert_eq(core::iovec_count(iov), 0);

        // CorkBuffer + PipeBuffer + RingBuffer error/edge paths
        var cb = core::new_cork_buffer();
        sub.assert_eq(core::cork_pending(cb), 0);
        sub.assert_true(core::cork_write_u24_be(cb, 0x01000000) == core::IoError.InvalidArgument);
        cb.append("ABC");
        cb.push('D');
        core::cork_consume(cb, 2);
        sub.assert_bytes_eq(core::cork_as_slice(cb), "CD");
        cb.resize(4);
        sub.assert_eq(cb.len, 4);
        cb.clear();
        sub.assert_eq(cb.len, 0);

        var pipe = core::new_pipe_buffer();
        let _w, e_pw = core::write(pipe, "hello");
        sub.assert_true(e_pw == core::IoError.None && core::readable_slice(pipe) == "hello");
        var pk: u8[3] = [0; 3];
        sub.assert_eq(core::peek(pipe, pk[..]), 3);
        sub.assert_true(core::advance_to(pipe, 3, 2) == core::IoError.InvalidArgument);
        let _, e_gws = core::get_write_span(pipe, 999999);
        sub.assert_true(e_gws == core::IoError.InvalidArgument);
        sub.assert_true(core::commit_write(pipe, -1) == core::IoError.InvalidArgument);
        core::complete_pipe(pipe);
        let e_cw = core::commit_write(pipe, 1);
        sub.assert_true(e_cw == core::IoError.Closed);
        core::pipe_reset(pipe);

        var rb = core::new_ring_buffer();
        let _, r_eof = core::read(rb, pk[..]);
        sub.assert_true(r_eof == core::IoError.Eof);
        sub.assert_true(core::commit_written(rb, -1) == core::IoError.InvalidArgument);
        let s1, s2 = core::write_slices(rb);
        s1[0] = 'x';
        let _ = s2;
        sub.assert_true(core::commit_written(rb, 1) == core::IoError.None);
        core::realign_ring(rb);
    };
}

fn test_io_reactor_host_and_pagemem(t: lit::T&) {
    t.run("Reactor/Host UFCS, PageMem, PageRing, Extra Crypto Guards") { sub =>
        // Io types & flags
        sub.assert_eq(core::interest_to_poll_flags(core::PollInterest.None), core::POLL_NONE);
        sub.assert_eq(core::interest_to_poll_flags(core::PollInterest.Read), core::POLL_READ);
        sub.assert_eq(core::interest_to_poll_flags(core::PollInterest.Write), core::POLL_WRITE);
        sub.assert_eq(core::interest_to_poll_flags(core::PollInterest.ReadWrite), core::POLL_READ | core::POLL_WRITE);
        let tcp_a = core::ConnectAddr.Tcp { host: "127.0.0.1", port: 8080 };
        let unix_a = core::ConnectAddr.Unix { path: "/tmp/w.sock" };
        let bad_unix = core::ConnectAddr.Unix { path: "" };
        sub.assert_true(core::is_valid_connect_addr(tcp_a) && core::is_valid_listen_addr(unix_a));
        sub.assert_false(core::is_valid_connect_addr(bad_unix) || core::is_valid_listen_addr(bad_unix));

        // translate_send_result & translate_recv_result + MockIo + RingBuffer + PipeBuffer adapters
        let b0, e0 = core::translate_send_result(-2, 10);
        let b1, e1 = core::translate_send_result(-1, 10);
        let b2, e2 = core::translate_send_result(3, 10);
        let b3, e3 = core::translate_send_result(10, 10);
        let _, e4 = core::translate_send_result(0, 0);
        sub.assert_true(b0 == 0 && e0 == core::IoError.WouldBlock && b1 == 0 && e1 == core::IoError.Closed);
        sub.assert_true(b2 == 3 && e2 == core::IoError.ShortWrite && b3 == 10 && e3 == core::IoError.None && e4 == core::IoError.None);
        let _, re0 = core::translate_recv_result(0);
        let _, re1 = core::translate_recv_result(-2);
        let _, re2 = core::translate_recv_result(-9);
        let rn, re3 = core::translate_recv_result(4);
        sub.assert_true(re0 == core::IoError.Eof && re1 == core::IoError.WouldBlock && re2 == core::IoError.Closed && rn == 4 && re3 == core::IoError.None);

        var rb = core::new_ring_buffer();
        var io_buf: u8[8] = [0; 8];
        let _, tr_wb = core::stream_try_recv(rb, io_buf[..]);
        sub.assert_true(tr_wb == core::IoError.WouldBlock);
        let ts_n, ts_e = core::stream_try_send(rb, "abcd");
        sub.assert_true(ts_n == 4 && ts_e == core::IoError.None);
        let rr, rerr = core::stream_try_recv(rb, io_buf[..]);
        sub.assert_true(rr == 4 && rerr == core::IoError.None);
        core::stream_close(rb);

        var pp = core::new_pipe_buffer();
        sub.assert_eq(core::stream_recv(pp, io_buf[..], 0), -2);
        sub.assert_eq(core::stream_send(pp, "xy"), 2);
        sub.assert_eq(core::stream_recv(pp, io_buf[..], 0), 2);
        core::stream_close(pp);
        sub.assert_eq(core::stream_send(pp, "xy"), -1);
        sub.assert_eq(core::stream_recv(pp, io_buf[..], 0), 0);

        // Host + DriverChain
        var mh = MockHost {};
        var chain = core::chain_io_drivers(core::NoOpIoDriver {}, core::NoOpIoDriver {});
        let lk, le = core::host_listen(mh, tcp_a, 16, 1, 64);
        sub.assert_true(le == core::IoError.None && core::io_link_owner(lk) == 16);
        let clk, cst = core::host_connect(mh, tcp_a, 16, 2);
        let hs, hse = core::host_send(mh, clk, "hi");
        sub.assert_true(cst == core::ConnectStatus.Connected && hs == 2 && hse == core::IoError.None);
        sub.assert_true(core::host_set_rx_paused(mh, clk, true) && core::host_shutdown_write(mh, clk));
        sub.assert_true(core::host_add_timer(mh, 5, 10, 16, 1) && core::host_cancel_timer(mh, 5));
        sub.assert_false(core::host_wake(mh, core::WakeToken {}));
        sub.assert_true(core::host_wake(mh, core::WakeToken { owner: 16, gen: 1, .. }));
        sub.assert_eq(core::host_step(mh, chain, 0, 0), 1);
        sub.assert_true(core::host_close(mh, clk) && core::host_close(mh, lk));

        // MmapFile & PageRing error paths on existing file
        let _, ok_mf0 = core::mmap_file_open("");
        sub.assert_false(ok_mf0);
        var mf, ok_mf = core::mmap_file_open("core.goose");
        sub.assert_true(ok_mf && mf.size > 0);
        var mfb: u8[8] = [0; 8];
        let mn, ok_mr = core::mmap_file_read(mf, 0, mfb[..]);
        let _, ok_ms = core::mmap_file_send(mf, 0, 4, -1);
        sub.assert_true(ok_mr && mn == 8 && !ok_ms);
        core::mmap_file_close(mf);

        var pr = core::PageRingBuffer {};
        sub.assert_eq(core::page_ring_discard(pr, 4), 0);
        sub.assert_eq(core::page_ring_recv(pr, -1), -1);
        if core::page_ring_init(pr, 4096) {
            sub.assert_gt(core::page_ring_available(pr), 0);
            sub.assert_eq(core::page_ring_peek(pr, io_buf[..]), 0);
            core::page_ring_clear(pr);
            core::page_ring_close(pr);
        }

        // Extra Crypto tag-mismatch / error-path checks
        let k16:      u8[16] = [1; 16];
        let k32:      u8[32] = [2; 32];
        let n12:      u8[12] = [3; 12];
        let zero_tag: u8[16] = [0; 16];
        var dec_out: u8[..32] = [];
        let bad_ct: u8[8] = [0xAA; 8];
        sub.assert_false(core::aes128_gcm_open(k16, n12, bad_ct[..], "", zero_tag, dec_out));
        var dst8: u8[8] = [0; 8];
        let _, ok_256i = core::aes256_gcm_open_into(k32, n12, bad_ct[..], "", zero_tag, dst8[..]);
        sub.assert_false(ok_256i);
        sub.assert_false(core::chacha20_poly1305_open(k32, n12, bad_ct[..], "", zero_tag, dec_out));
        let p384_zero: u8[48] = [0; 48];
        let _, ok_p384z = core::p384_ecdh_shared_secret(p384_zero, "bad");
        sub.assert_false(ok_p384z);
    };
}

fn main() {
    let runner = lit::new_runner("Core Root, IO, Time & Crypto Deep Verification Suite");
    lit::run_case(runner, "1. Root, UFCS, TickTimer & Sim", test_root_and_ufcs);
    lit::run_case(runner, "2. IO Cursor, Builder, Vec, Pipe, Cork & Ring", test_io_cursor_vec_pipe_cork_ring);
    lit::run_case(runner, "3. Reactor, Host, PageMem, PageRing & Crypto Guards", test_io_reactor_host_and_pagemem);
    assert(lit::finish(runner));
}
