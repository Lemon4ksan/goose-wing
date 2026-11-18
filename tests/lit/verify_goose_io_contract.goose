// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of the `goose-io` v0.1 contract adapter (`net/goose_io.goose`) over `wing::NetHost`.
// Covers compile-time `require_*` verifiers, deferred `BadAddress` dial failure with `set_user`,
// live TCP loopback `listen` + `dial` + `HalfClose` + `PassEnd`, episode-based `Writable`
// backpressure, and multi-library composition (`tag = 1` front server + `tag = 2/3` fakepg).
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wing.net.goose_io;

const TAG_BAD_A:     u16 = 10;
const TAG_BAD_B:     u16 = 11;
const TAG_TCP_SRV:   u16 = 20;
const TAG_TCP_CLI:   u16 = 21;
const TAG_VIRT_TX:   u16 = 30;
const TAG_VIRT_RX:   u16 = 31;
const TAG_FRONT_SRV: u16 = 1;
const TAG_FAKEPG_CL: u16 = 2;
const TAG_FAKEPG_SV: u16 = 3;
const TAG_FRONT_CLI: u16 = 4;

fn format_loopback_addr<B>(port: u16, out: B&) {
    out.clear();
    out.append("127.0.0.1:");
    (port as u32).format_u32_dec(out);
}

// ---- 1. Compile-Time Verifiers & Pure Value Predicates ---------------------

fn verify_generic_all_groups<Io>(io: Io&) {
    goose_io::require_core(io);
    goose_io::require_half_close(io);
    goose_io::require_sizing(io);
    goose_io::require_abort(io);
    goose_io::require_inspection(io);
}

fn test_contract_types_and_verifiers() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);
    verify_generic_all_groups(io);

    let zero_lnk = goose_io::Link { .. };
    let valid_lnk = goose_io::Link { slot: 0, gen: 1 };
    assert(!zero_lnk.is_valid() && valid_lnk.is_valid());
    assert(!zero_lnk.same(zero_lnk) && valid_lnk.same(valid_lnk));

    let zero_lst = goose_io::Listener { .. };
    let valid_lst = goose_io::Listener { id: 1 };
    assert(!zero_lst.is_listener() && valid_lst.is_listener());
    assert(!zero_lst.same(zero_lst) && valid_lst.same(valid_lst));

    let v4_addr, ok_v4 = goose_io::parse_address("127.0.0.1:5432");
    assert(ok_v4 && !v4_addr.is_empty() && v4_addr.text[..] == "127.0.0.1:5432");
    let v6_addr, ok_v6 = goose_io::parse_address("[2001:0db8::1]:8080");
    assert(ok_v6 && v6_addr.text[..] == "[2001:db8::1]:8080");
    let bad_host, ok_bh = goose_io::parse_address("localhost:80");
    assert(!ok_bh && bad_host.is_empty());
    let _, ok_zone = goose_io::parse_address("[fe80::1%eth0]:80");
    assert(!ok_zone);

    let cf_why = goose_io::CloseReason.ConnectFailed { kind: goose_io::ConnectFailure.BadAddress };
    let ls_why = goose_io::CloseReason.LoopSpecific { code: 77 };
    assert(cf_why.is_connect_failed() && cf_why.is_portable());
    assert(!ls_why.is_connect_failed() && !ls_why.is_portable());

    let ev_tick = goose_io::Event.Tick { now_ms: 100 };
    assert(!ev_tick.is_link_event() && ev_tick.tag_of() == 0 && !ev_tick.link_of().is_valid());
    let ev_open = goose_io::Event.Opened {
        link: valid_lnk, tag: 9, user: 55, listener: zero_lst,
    };
    assert(ev_open.is_link_event() && ev_open.tag_of() == 9 && ev_open.user_of() == 55);
    assert(ev_open.link_of().same(valid_lnk));

    print("TEST1_CONTRACT_VERIFIERS_AND_TYPES: OK");
}

// ---- 2. Deferred Immediate Dial Failure + `set_user` Preservation ----------

struct BadDialProbe {
    lnk_a:            goose_io::Link = goose_io::Link { .. },
    lnk_b:            goose_io::Link = goose_io::Link { .. },
    saw_opened:       bool           = false,
    closed_a_ok:      bool           = false,
    closed_b_ok:      bool           = false,
    user_live_in_cls: bool           = false,
    stale_after_cls:  bool           = false,
    pass_ends:        i64            = 0,
}

fn test_deferred_bad_address_dial() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);

    let bad_lst, bad_lerr = io.listen("localhost:8080", 1);
    assert(!bad_lst.is_listener() && bad_lerr.failed());
    assert(bad_lerr.kind == goose_io::ListenErrorKind.BadAddress);

    var probe = BadDialProbe { .. };
    probe.lnk_a = io.dial("localhost:80", TAG_BAD_A, 500);
    probe.lnk_b = io.dial("[::1%eth0]:80", TAG_BAD_B, 500);
    assert(probe.lnk_a.is_valid() && probe.lnk_b.is_valid());
    assert(!probe.lnk_a.same(probe.lnk_b));
    assert(io.send(probe.lnk_a, "early") == goose_io::SendStatus.NotOpen);

    io.set_user(probe.lnk_a, 42);
    io.set_user(probe.lnk_b, 99);
    assert(io.user(probe.lnk_a) == 42 && io.user(probe.lnk_b) == 99);

    io.serve() { loop_ref, ev =>
        match ev {
            Opened _ => {
                probe.saw_opened = true;
            },
            Closed c => {
                if c.link.same(probe.lnk_a) && c.tag == TAG_BAD_A && c.user == 42 {
                    let is_bad = match c.why {
                        ConnectFailed f => f.kind == goose_io::ConnectFailure.BadAddress,
                        _ => false,
                    };
                    probe.closed_a_ok = is_bad;
                    probe.user_live_in_cls = (loop_ref.user(probe.lnk_a) == 42) &&
                        loop_ref.peer_address(probe.lnk_a).is_empty();
                } else if c.link.same(probe.lnk_b) && c.tag == TAG_BAD_B && c.user == 99 {
                    let is_bad = match c.why {
                        ConnectFailed f => f.kind == goose_io::ConnectFailure.BadAddress,
                        _ => false,
                    };
                    probe.closed_b_ok = is_bad;
                }
                if probe.closed_a_ok && probe.closed_b_ok {
                    loop_ref.stop(0);
                    assert(loop_ref.draining());
                }
            },
            PassEnd => {
                probe.pass_ends = core::add_sat_i64(probe.pass_ends, 1);
                if probe.closed_a_ok {
                    probe.stale_after_cls = (loop_ref.user(probe.lnk_a) == 0) &&
                        (loop_ref.send(probe.lnk_a, "x") == goose_io::SendStatus.Closed);
                }
            },
            _ => {},
        };
    };

    assert(!probe.saw_opened);
    assert(probe.closed_a_ok && probe.closed_b_ok);
    assert(probe.user_live_in_cls && probe.stale_after_cls);
    assert(probe.pass_ends >= 1 && !io.draining());
    print("TEST2_DEFERRED_BAD_ADDRESS_DIAL: OK");
}

// ---- 3. Real TCP Loopback: Listen, Dial, Send2, HalfClose, PeerEof, Closed -

struct TcpHalfCloseState {
    srv_lst:       goose_io::Listener = goose_io::Listener { .. },
    srv_link:      goose_io::Link     = goose_io::Link { .. },
    cli_link:      goose_io::Link     = goose_io::Link { .. },
    expected_peer: u8[..56]           = [],
    srv_rx:        u8[..256]          = [],
    cli_rx:        u8[..256]          = [],
    srv_opened:    bool               = false,
    cli_opened:    bool               = false,
    peer_addr_ok:  bool               = false,
    srv_saw_eof:   bool               = false,
    cli_saw_eof:   bool               = false,
    srv_closed:    bool               = false,
    cli_closed:    bool               = false,
    pass_ends:     i64                = 0,
}

fn test_tcp_loopback_and_half_close() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);

    let lst1, err1 = io.listen("127.0.0.1:0", TAG_TCP_SRV);
    assert(!err1.failed() && lst1.is_listener() && lst1.id == 1);
    let port1 = io.listener_port(lst1);
    assert(port1 > 0);

    var addr_buf: u8[..56] = [];
    format_loopback_addr(port1, addr_buf);

    // Duplicate bind on active port yields AddressInUse; stopping listener frees port & never reuses ID.
    let dup_lst, dup_err = io.listen(addr_buf[..], TAG_TCP_SRV);
    assert(!dup_lst.is_listener() && dup_err.kind == goose_io::ListenErrorKind.AddressInUse);
    io.stop_listening(lst1);
    assert(io.listener_port(lst1) == 0);

    let lst2, err2 = io.listen("127.0.0.1:0", TAG_TCP_SRV);
    assert(!err2.failed() && lst2.is_listener() && lst2.id == 2);
    let port2 = io.listener_port(lst2);
    assert(port2 > 0);
    format_loopback_addr(port2, addr_buf);

    var st = TcpHalfCloseState { srv_lst: lst2, .. };
    let _ = st.expected_peer.try_set(addr_buf[..]);
    st.cli_link = io.dial(addr_buf[..], TAG_TCP_CLI, 2000);
    io.set_user(st.cli_link, 707);
    assert(io.max_send() >= 4096);

    io.serve() { loop_ref, ev =>
        match ev {
            Opened o => {
                if o.tag == TAG_TCP_SRV && o.listener.same(st.srv_lst) {
                    st.srv_link = o.link;
                    st.srv_opened = true;
                    loop_ref.set_user(o.link, 808);
                    loop_ref.set_keep_open_on_eof(o.link, true);
                } else if o.tag == TAG_TCP_CLI && o.link.same(st.cli_link) && o.user == 707 {
                    st.cli_opened = true;
                    let pa = loop_ref.peer_address(o.link);
                    st.peer_addr_ok = (pa.text[..] == st.expected_peer[..]);
                    assert(loop_ref.send_room(o.link) == loop_ref.max_send());
                    let s_res = loop_ref.send2(o.link, "PING_", "HALFCLOSE");
                    assert(s_res == goose_io::SendStatus.Sent);
                    loop_ref.shutdown_write(o.link);
                    assert(loop_ref.send(o.link, "after_fin") == goose_io::SendStatus.Closed);
                }
            },
            Data d => {
                if d.tag == TAG_TCP_SRV && d.user == 808 {
                    let _ = st.srv_rx.try_append(d.bytes);
                } else if d.tag == TAG_TCP_CLI && d.user == 707 {
                    let _ = st.cli_rx.try_append(d.bytes);
                }
            },
            PeerEof p => {
                if p.tag == TAG_TCP_SRV && p.user == 808 {
                    st.srv_saw_eof = true;
                    // Link stayed open on EOF because `set_keep_open_on_eof(true)` was configured.
                    let reply_st = loop_ref.send(p.link, "PONG_AFTER_EOF");
                    assert(reply_st == goose_io::SendStatus.Sent);
                    loop_ref.close(p.link);
                } else if p.tag == TAG_TCP_CLI && p.user == 707 {
                    st.cli_saw_eof = true;
                }
            },
            Closed c => {
                if c.tag == TAG_TCP_SRV && c.user == 808 {
                    assert(c.why == goose_io::CloseReason.Local);
                    st.srv_closed = true;
                } else if c.tag == TAG_TCP_CLI && c.user == 707 {
                    assert(loop_ref.peer_address(c.link).text[..] == st.expected_peer[..]);
                    st.cli_closed = true;
                }
                if st.srv_closed && st.cli_closed {
                    loop_ref.stop(0);
                }
            },
            PassEnd => {
                st.pass_ends = core::add_sat_i64(st.pass_ends, 1);
            },
            _ => {},
        };
    };

    assert(st.srv_opened && st.cli_opened && st.peer_addr_ok);
    assert(st.srv_rx[..] == "PING_HALFCLOSE");
    assert(st.cli_rx[..] == "PONG_AFTER_EOF");
    assert(st.srv_saw_eof && st.cli_saw_eof);
    assert(st.srv_closed && st.cli_closed && st.pass_ends >= 2);
    print("TEST3_TCP_LOOPBACK_HALFCLOSE: OK");
}

// ---- 4. Episode-Based `Writable`, `pause_reading`, `tick_by`, and `reset` --

struct EpisodeProbe {
    tx_link:       goose_io::Link = goose_io::Link { .. },
    rx_link:       goose_io::Link = goose_io::Link { .. },
    tx_opened:     bool           = false,
    rx_opened:     bool           = false,
    filled_once:   bool           = false,
    writable_cnt:  i64            = 0,
    room_on_write: i64            = 0,
    rx_bytes:      i64            = 0,
    tick_fired:    bool           = false,
    tx_closed:     bool           = false,
}

fn test_episode_writable_and_tick() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);

    let la, lb, ok_v = goose_io::open_virtual_pair(io, TAG_VIRT_TX, TAG_VIRT_RX);
    assert(ok_v && la.is_valid() && lb.is_valid());
    io.pause_reading(lb, true);
    let t0 = io.now_ms();
    io.tick_by(core::add_sat_i64(t0, 5));

    var probe = EpisodeProbe { tx_link: la, rx_link: lb, .. };
    var chunk_16k: u8[16384] = [0x5A; 16384];
    var chunk_8k:  u8[8192]  = [0x42; 8192];
    var oversize:  u8[65537] = [0x33; 65537];

    io.serve() { loop_ref, ev =>
        match ev {
            Opened o => {
                if o.link.same(probe.tx_link) { probe.tx_opened = true; }
                if o.link.same(probe.rx_link) { probe.rx_opened = true; }
                if probe.tx_opened && probe.rx_opened && !probe.filled_once {
                    probe.filled_once = true;
                    assert(loop_ref.send(probe.tx_link, "") == goose_io::SendStatus.Sent);
                    assert(loop_ref.send(probe.tx_link, oversize[..]) == goose_io::SendStatus.TooLarge);
                    // Send 4 x 16KB = 64KB (4KB in virtual pipe + 60KB queued -> 4KB room left).
                    for _ in 4 {
                        assert(loop_ref.send(probe.tx_link, chunk_16k[..]) == goose_io::SendStatus.Sent);
                    }
                    assert(loop_ref.send_room(probe.tx_link) == 4096);
                    // Refuse 8KB, then 16KB in the same episode -> `max_refused` upgrades to 16384.
                    assert(loop_ref.send(probe.tx_link, chunk_8k[..]) == goose_io::SendStatus.Full);
                    assert(loop_ref.send(probe.tx_link, chunk_16k[..]) == goose_io::SendStatus.Full);
                }
            },
            Tick tk => {
                assert(tk.now_ms >= t0);
                if !probe.tick_fired {
                    probe.tick_fired = true;
                    loop_ref.pause_reading(probe.rx_link, false);
                }
            },
            Data d => {
                if d.link.same(probe.rx_link) {
                    probe.rx_bytes = core::add_sat_i64(probe.rx_bytes, d.bytes.len);
                }
            },
            Writable w => {
                if w.link.same(probe.tx_link) {
                    probe.writable_cnt = core::add_sat_i64(probe.writable_cnt, 1);
                    probe.room_on_write = loop_ref.send_room(probe.tx_link);
                    loop_ref.reset(probe.tx_link);
                    loop_ref.reset(probe.rx_link);
                }
            },
            Closed c => {
                if c.link.same(probe.tx_link) {
                    assert(c.why == goose_io::CloseReason.Local);
                    probe.tx_closed = true;
                    loop_ref.stop(0);
                }
            },
            _ => {},
        };
    };

    assert(probe.tick_fired);
    assert(probe.writable_cnt == 1 && probe.room_on_write >= 16384);
    assert(probe.rx_bytes >= 12288 && probe.rx_bytes < 65536 && probe.tx_closed);
    print("TEST4_EPISODE_WRITABLE_AND_TICK: OK");
}

// ---- 5. Multi-Library Composition (`tag = 1` Front + `tag = 2/3` FakePg) ---

// Standalone simulated `fakepg` server library (`tag = 3`), written strictly to `goose-io`.
struct FakePgServerLib {
    listener: goose_io::Listener = goose_io::Listener { .. },
    conn:     goose_io::Link     = goose_io::Link { .. },
    rx_buf:   u8[..1024]         = [],
    queries:  i64                = 0,
}

fn fakepg_server_start<Io>(srv: FakePgServerLib&, io: Io&, tag: u16) -> u16 {
    goose_io::require_core(io);
    let lst, err = io.listen("127.0.0.1:0", tag);
    assert(!err.failed() && lst.is_listener());
    srv.listener = lst;
    return io.listener_port(lst);
}

fn fakepg_server_on_event<Io>(srv: FakePgServerLib&, io: Io&, ev: goose_io::Event) {
    match ev {
        Opened o => {
            srv.conn = o.link;
        },
        Data d => {
            let _ = srv.rx_buf.try_append(d.bytes);
            while true {
                let nl = srv.rx_buf[..].index_of_byte('\n');
                guard nl >= 0 else { break; }
                let line = srv.rx_buf[..nl];
                let key, ok_q = line.strip_prefix("Q:");
                if ok_q {
                    srv.queries = core::add_sat_i64(srv.queries, 1);
                    var reply: u8[..128] = [];
                    let _ = reply.try_append("R:");
                    let _ = reply.try_append(key);
                    let _ = reply.try_append("=ok\n");
                    assert(io.send(srv.conn, reply[..]) == goose_io::SendStatus.Sent);
                }
                core::compact_wire_buffer(srv.rx_buf, core::add_sat_i64(nl, 1));
            }
        },
        _ => {},
    };
}

// Standalone simulated `fakepg` pipelined client library (`tag = 2`), oblivious to HTTP/front-end.
struct PgPendingItem {
    req_token: u32      = 0,
    key:       u8[..32] = [],
    result:    u8[..64] = [],
    sent:      bool     = false,
    done:      bool     = false,
    in_use:    bool     = false,
}

struct FakePgClientLib {
    conn:      goose_io::Link   = goose_io::Link { .. },
    connected: bool             = false,
    rx_buf:    u8[..1024]       = [],
    queue:     PgPendingItem[8] = [PgPendingItem { .. }; 8],
}

fn fakepg_client_connect<Io>(cli: FakePgClientLib&, io: Io&, addr: const u8[:], tag: u16) {
    goose_io::require_core(io);
    cli.conn = io.dial(addr, tag, 2000);
}

fn fakepg_client_flush<Io>(cli: FakePgClientLib&, io: Io&) {
    guard cli.connected else { return; }
    for i in 8 {
        if cli.queue[i].in_use && !cli.queue[i].sent {
            var msg: u8[..64] = [];
            let _ = msg.try_append("Q:");
            let _ = msg.try_append(cli.queue[i].key[..]);
            let _ = msg.try_append("\n");
            if io.send(cli.conn, msg[..]) == goose_io::SendStatus.Sent {
                cli.queue[i].sent = true;
            }
        }
    }
}

fn fakepg_client_submit<Io>(cli: FakePgClientLib&, io: Io&, token: u32, key: const u8[:]) {
    for i in 8 {
        if !cli.queue[i].in_use {
            cli.queue[i] = PgPendingItem { req_token: token, in_use: true, .. };
            let _ = cli.queue[i].key.try_set(key);
            fakepg_client_flush(cli, io);
            return;
        }
    }
}

fn fakepg_client_take_done(cli: FakePgClientLib&, out_val: u8[..64]&) -> u32, bool {
    out_val.clear();
    for i in 8 {
        if cli.queue[i].in_use && cli.queue[i].done {
            let tok = cli.queue[i].req_token;
            let _ = out_val.try_set(cli.queue[i].result[..]);
            cli.queue[i] = PgPendingItem { .. };
            return tok, true;
        }
    }
    return 0, false;
}

fn fakepg_client_on_event<Io>(cli: FakePgClientLib&, io: Io&, ev: goose_io::Event) {
    match ev {
        Opened _ => {
            cli.connected = true;
            fakepg_client_flush(cli, io);
        },
        Data d => {
            let _ = cli.rx_buf.try_append(d.bytes);
            while true {
                let nl = cli.rx_buf[..].index_of_byte('\n');
                guard nl >= 0 else { break; }
                let line = cli.rx_buf[..nl];
                for i in 8 {
                    if cli.queue[i].in_use && cli.queue[i].sent && !cli.queue[i].done {
                        let _ = cli.queue[i].result.try_set(line);
                        cli.queue[i].done = true;
                        break;
                    }
                }
                core::compact_wire_buffer(cli.rx_buf, core::add_sat_i64(nl, 1));
            }
        },
        _ => {},
    };
}

// Standalone front-end TCP request library (`tag = 1`), oblivious to `fakepg` sockets.
struct FrontRequestSlot {
    token:  u32      = 0,
    db_key: u8[..32] = [],
    ready:  bool     = false,
}

struct FrontServerLib {
    listener:   goose_io::Listener  = goose_io::Listener { .. },
    cli_conn:   goose_io::Link      = goose_io::Link { .. },
    rx_buf:     u8[..1024]          = [],
    next_token: u32                 = 1,
    pending_db: FrontRequestSlot[8] = [FrontRequestSlot { .. }; 8],
}

fn front_server_start<Io>(srv: FrontServerLib&, io: Io&, tag: u16) -> u16 {
    goose_io::require_core(io);
    goose_io::require_sizing(io);
    let lst, err = io.listen("127.0.0.1:0", tag);
    assert(!err.failed() && lst.is_listener());
    srv.listener = lst;
    return io.listener_port(lst);
}

fn front_server_on_event<Io>(srv: FrontServerLib&, io: Io&, ev: goose_io::Event) {
    match ev {
        Opened o => {
            srv.cli_conn = o.link;
            io.set_user(o.link, 100);
        },
        Data d => {
            let _ = srv.rx_buf.try_append(d.bytes);
            while true {
                let nl = srv.rx_buf[..].index_of_byte('\n');
                guard nl >= 0 else { break; }
                let line = srv.rx_buf[..nl];
                let key, ok_get = line.strip_prefix("GET ");
                if ok_get {
                    for i in 8 {
                        if !srv.pending_db[i].ready {
                            let tok = srv.next_token;
                            srv.next_token = core::add_sat_u64(tok, 1) as u32;
                            srv.pending_db[i] = FrontRequestSlot { token: tok, ready: true, .. };
                            let _ = srv.pending_db[i].db_key.try_set(key);
                            break;
                        }
                    }
                }
                core::compact_wire_buffer(srv.rx_buf, core::add_sat_i64(nl, 1));
            }
        },
        _ => {},
    };
}

fn front_server_complete_db<Io>(srv: FrontServerLib&, io: Io&, _tok: u32, row: const u8[:]) {
    let st = io.send2(srv.cli_conn, row, "\n");
    assert(st == goose_io::SendStatus.Sent);
}

struct ComposedApp {
    front:    FrontServerLib  = FrontServerLib { .. },
    pg_cli:   FakePgClientLib = FakePgClientLib { .. },
    pg_srv:   FakePgServerLib = FakePgServerLib { .. },
    ext_cli:  goose_io::Link  = goose_io::Link { .. },
    ext_rx:   u8[..512]       = [],
    finished: bool            = false,
}

fn pump_composed_app<Io>(app: ComposedApp&, io: Io&) {
    for i in 8 {
        if app.front.pending_db[i].ready {
            let tok = app.front.pending_db[i].token;
            fakepg_client_submit(app.pg_cli, io, tok, app.front.pending_db[i].db_key[..]);
            app.front.pending_db[i] = FrontRequestSlot { .. };
        }
    }
    var row_buf: u8[..64] = [];
    while true {
        let tok, ok = fakepg_client_take_done(app.pg_cli, row_buf);
        guard ok else { break; }
        front_server_complete_db(app.front, io, tok, row_buf[..]);
    }
}

fn test_multi_library_composition() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);

    var app = ComposedApp { .. };
    let pg_port = fakepg_server_start(app.pg_srv, io, TAG_FAKEPG_SV);
    let front_port = front_server_start(app.front, io, TAG_FRONT_SRV);

    var pg_addr: u8[..56] = [];
    format_loopback_addr(pg_port, pg_addr);
    fakepg_client_connect(app.pg_cli, io, pg_addr[..], TAG_FAKEPG_CL);

    var front_addr: u8[..56] = [];
    format_loopback_addr(front_port, front_addr);
    app.ext_cli = io.dial(front_addr[..], TAG_FRONT_CLI, 2000);

    io.serve() { loop_ref, ev =>
        let tag = ev.tag_of();
        if tag == TAG_FRONT_SRV {
            front_server_on_event(app.front, loop_ref, ev);
        } else if tag == TAG_FAKEPG_CL {
            fakepg_client_on_event(app.pg_cli, loop_ref, ev);
        } else if tag == TAG_FAKEPG_SV {
            fakepg_server_on_event(app.pg_srv, loop_ref, ev);
        } else if tag == TAG_FRONT_CLI {
            match ev {
                Opened o => {
                    // Send two pipelined front-end requests back-to-back.
                    let s = loop_ref.send(o.link, "GET acct_1\nGET acct_2\n");
                    assert(s == goose_io::SendStatus.Sent);
                },
                Data d => {
                    let _ = app.ext_rx.try_append(d.bytes);
                    if core::contains(app.ext_rx[..], "R:acct_1=ok\nR:acct_2=ok\n") && !app.finished {
                        app.finished = true;
                        loop_ref.close(app.ext_cli);
                        loop_ref.close(app.front.cli_conn);
                        loop_ref.close(app.pg_cli.conn);
                        loop_ref.close(app.pg_srv.conn);
                        loop_ref.stop(500);
                    }
                },
                _ => {},
            };
        }
        if ev == goose_io::Event.PassEnd {
            pump_composed_app(app, loop_ref);
        }
    };

    assert(app.finished);
    assert(app.pg_srv.queries == 2);
    assert(app.ext_rx[..] == "R:acct_1=ok\nR:acct_2=ok\n");
    print("TEST5_MULTI_LIBRARY_COMPOSITION: OK");
}

// ---- 6. Unbounded `PollBatch` (> 512 raw events in a single poll pass) ----

fn test_unbounded_poll_batch_over_512() {
    var io = goose_io::HostLoop { .. };
    defer goose_io::close_host_loop(io);

    var batch = goose_io::PollBatch { .. };
    for i in 600 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data,
            tag:  i as u64,
            data: "Z",
            ..
        };
        core::on_link_event(batch, io.host, ev);
    }
    assert(batch.events.len == 600 && batch.bytes.len == 600);
    for i in 600 {
        assert(batch.events[i].tag == (i as u64));
        assert(batch.events[i].data_off == (i as u32) && batch.events[i].data_len == 1);
        let off = batch.events[i].data_off as i64;
        assert(batch.bytes[off..off + 1] == "Z");
    }
    print("TEST6_POLL_BATCH_OVER_512: OK");
}

fn main() {
    test_contract_types_and_verifiers();
    test_deferred_bad_address_dial();
    test_tcp_loopback_and_half_close();
    test_episode_writable_and_tick();
    test_multi_library_composition();
    test_unbounded_poll_batch_over_512();
}

// CHECK: TEST1_CONTRACT_VERIFIERS_AND_TYPES: OK
// CHECK: TEST2_DEFERRED_BAD_ADDRESS_DIAL: OK
// CHECK: TEST3_TCP_LOOPBACK_HALFCLOSE: OK
// CHECK: TEST4_EPISODE_WRITABLE_AND_TICK: OK
// CHECK: TEST5_MULTI_LIBRARY_COMPOSITION: OK
// CHECK: TEST6_POLL_BATCH_OVER_512: OK
