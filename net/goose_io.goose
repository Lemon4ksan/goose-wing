// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation `goose-io` v0.1 contract adapter over `net::Host`.
// Enables standalone `goose-io` protocol libraries (HTTP servers, database wire
// clients, RPC engines) to compose side-by-side on a single `goose-wing` event loop.
namespace goose_io;

import std;
import os;
import core from "..";
import net.driver;
import .io_host;

const HOST_LOOP_MAX_SEND:       i64 = 65536;
const HOST_LOOP_MIN_POOL_ALLOC: i64 = 1024;
const HOST_LOOP_TICK_PERIOD_MS: i64 = 100;
const HOST_LOOP_OWNER_ID:       u16 = 600;
const HOST_LOOP_TIMER_ID:       u64 = 900001;
const HOST_LOOP_BACKLOG:        i32 = 128;
const MAX_PORT_NUMBER:          u32 = 65535;
const MIN_UNPRIVILEGED_PORT:    u16 = 1024;
const MAX_GEN_VALUE:            u32 = 0xFFFFFFFF;

// ---- goose-io v0.1 Contract Types & Predicates -----------------------------

struct Link {
    slot: u32 = 0,
    gen:  u32 = 0,
}

inline fn is_valid(l: Link) -> bool {
    return l.gen != 0;
}

inline fn same(a: Link, b: Link) -> bool {
    return a.gen != 0 && a.slot == b.slot && a.gen == b.gen;
}

struct Listener {
    id: u32 = 0,
}

inline fn is_listener(l: Listener) -> bool {
    return l.id != 0;
}

inline fn same(a: Listener, b: Listener) -> bool {
    return a.id != 0 && a.id == b.id;
}

struct Address {
    text: u8[..56] = [],
}

inline fn is_empty(a: Address) -> bool {
    return a.text.len == 0;
}

enum SendStatus {
    Sent,
    Full,
    TooLarge,
    NotOpen,
    Closed,
}

enum ConnectFailure {
    Refused,
    TimedOut,
    Unreachable,
    Denied,
    NoResources,
    BadAddress,
    Other,
}

enum CloseReason {
    PeerClosed,
    PeerReset,
    ConnectFailed { kind: ConnectFailure },
    IdleTimeout,
    HalfCloseTimeout,
    Local,
    Shutdown,
    Error,
    LoopSpecific { code: i32 },
}

inline fn is_connect_failed(r: CloseReason) -> bool {
    return match r {
        ConnectFailed _ => true,
        _ => false,
    };
}

inline fn is_portable(r: CloseReason) -> bool {
    return match r {
        LoopSpecific _ => false,
        _ => true,
    };
}

enum ListenErrorKind {
    None,
    AddressInUse,
    BadAddress,
    Denied,
    NoResources,
    Other,
}

struct ListenError {
    kind: ListenErrorKind = ListenErrorKind.None,
    code: i32             = 0,
}

inline fn failed(e: ListenError) -> bool {
    return e.kind != ListenErrorKind.None;
}

enum Event {
    Opened { link: Link, tag: u16, user: u32, listener: Listener },
    Data { link: Link, tag: u16, user: u32, bytes: const u8[:] },
    Writable { link: Link, tag: u16, user: u32 },
    PeerEof { link: Link, tag: u16, user: u32 },
    Closed { link: Link, tag: u16, user: u32, why: CloseReason },
    Tick { now_ms: i64 },
    PassEnd,
}

inline fn is_link_event(ev: Event) -> bool {
    return match ev {
        Tick _ => false,
        PassEnd => false,
        _ => true,
    };
}

inline fn tag_of(ev: Event) -> u16 {
    return match ev {
        Opened x => x.tag,
        Data x => x.tag,
        Writable x => x.tag,
        PeerEof x => x.tag,
        Closed x => x.tag,
        _ => 0,
    };
}

inline fn user_of(ev: Event) -> u32 {
    return match ev {
        Opened x => x.user,
        Data x => x.user,
        Writable x => x.user,
        PeerEof x => x.user,
        Closed x => x.user,
        _ => 0,
    };
}

inline fn link_of(ev: Event) -> Link {
    return match ev {
        Opened x => x.link,
        Data x => x.link,
        Writable x => x.link,
        PeerEof x => x.link,
        Closed x => x.link,
        _ => Link { .. },
    };
}

// ---- Compile-Time Contract Verifiers ---------------------------------------

fn require_core<Io>(io: Io&) {
    if false {
        let lst, lerr = io.listen("127.0.0.1:0", 0 as u16);
        let _lp:   Listener    = lst;
        let _le:   ListenError = lerr;
        let _port: u16         = io.listener_port(lst);
        let lnk:   Link        = io.dial("127.0.0.1:1", 0 as u16, 1000 as i64);
        var sample: u8[1] = [0];
        let _st: SendStatus = io.send(lnk, sample[..]);
        let _ms: i64        = io.max_send();
        io.pause_reading(lnk, true);
        io.close(lnk);
        io.set_user(lnk, 0 as u32);
        let _now: i64 = io.now_ms();
        io.tick_by(0 as i64);
        io.serve() { loop_ref, ev =>
            let _ev_chk: Event = ev;
            loop_ref.stop(0 as i64);
        };
        io.stop(0 as i64);
        let _dr: bool = io.draining();
    }
}

fn require_half_close<Io>(io: Io&) {
    if false {
        let lnk = Link { .. };
        io.set_keep_open_on_eof(lnk, true);
        io.shutdown_write(lnk);
    }
}

fn require_sizing<Io>(io: Io&) {
    if false {
        let lnk = Link { .. };
        var head: u8[1] = [0];
        var tail: u8[1] = [0];
        let _room: i64        = io.send_room(lnk);
        let _st:   SendStatus = io.send2(lnk, head[..], tail[..]);
    }
}

fn require_abort<Io>(io: Io&) {
    if false {
        let lnk = Link { .. };
        io.reset(lnk);
    }
}

fn require_inspection<Io>(io: Io&) {
    if false {
        let lnk = Link { .. };
        let _peer: Address = io.peer_address(lnk);
        let _usr:  u32     = io.user(lnk);
        io.stop_listening(Listener { .. });
    }
}

// ---- Strict Numeric Endpoint Parser ----------------------------------------

enum EndpointPortRule {
    NonZeroOnly,
    AllowZero,
}

// Parses a strict decimal TCP port (0..65535) rejecting leading zeros and signs.
//
// Example:
//   port_str = "5432", rule = EndpointPortRule.NonZeroOnly
//   returns: 5432, ok = true
fn parse_endpoint_port(port_str: const u8[:], rule: EndpointPortRule) -> u16, bool {
    guard port_str.len >= 1 && port_str.len <= 5 else { return 0, false; }
    guard port_str.len == 1 || port_str[0] != '0' else { return 0, false; }
    let val, ok = port_str.parse_u32_dec();
    guard ok && val <= MAX_PORT_NUMBER else { return 0, false; }
    guard val != 0 || rule == EndpointPortRule.AllowZero else { return 0, false; }
    return val as u16, true;
}

// Parses a strict 4-octet decimal IPv4 literal rejecting hostnames and leading zeros.
//
// Example:
//   ip_str = "127.0.0.1"
//   returns: true
fn parse_strict_ipv4(ip_str: const u8[:]) -> bool {
    guard ip_str.len >= 7 && ip_str.len <= 15 else { return false; }
    var rest = ip_str;
    for _ in 3 {
        let dot = rest.index_of_byte('.');
        guard dot > 0 else { return false; }
        let _, ok = core::parse_ipv4_decimal_octet(rest[..dot]);
        guard ok else { return false; }
        rest = rest[core::add_sat_i64(dot, 1)..];
    }
    let _, ok_last = core::parse_ipv4_decimal_octet(rest);
    return ok_last;
}

struct ParsedEndpoint {
    canonical: Address  = Address { .. },
    host:      u8[..46] = [],
    port:      u16      = 0,
    is_ipv6:   bool     = false,
}

// Parses a bracketed numeric IPv6 endpoint `[ip]:port` rejecting `%zone` identifiers.
//
// Example:
//   raw = "[::1]:8080", rule = EndpointPortRule.NonZeroOnly
//   returns: ParsedEndpoint { canonical: "[::1]:8080", host: "::1", port: 8080, is_ipv6: true }, ok = true
fn parse_bracketed_ipv6_endpoint(raw: const u8[:], rule: EndpointPortRule) -> ParsedEndpoint, bool {
    var out = ParsedEndpoint { is_ipv6: true, .. };
    let close_idx = raw.index_of_byte(']');
    guard close_idx > 1 && core::add_sat_i64(close_idx, 2) < raw.len else { return out, false; }
    guard raw[core::add_sat_i64(close_idx, 1)] == ':' else { return out, false; }
    let ip_part = raw[1..close_idx];
    let port_part = raw[core::add_sat_i64(close_idx, 2)..];
    guard !ip_part.contains_byte('%') && !ip_part.contains_byte('[') else { return out, false; }
    let port, ok_port = parse_endpoint_port(port_part, rule);
    guard ok_port else { return out, false; }
    let _, ok_oct = core::parse_ipv6_octets(ip_part);
    guard ok_oct else { return out, false; }
    guard core::parse_and_compress_ipv6(ip_part, out.host) else { return out, false; }
    guard out.canonical.text.try_push('[') else { return out, false; }
    guard out.canonical.text.try_append(out.host[..]) else { return out, false; }
    guard out.canonical.text.try_append("]:") else { return out, false; }
    core::format_u32_dec(port, out.canonical.text);
    out.port = port;
    return out, true;
}

// Parses a strict numeric `"ip:port"` (IPv4) or `"[ip]:port"` (IPv6) endpoint.
// Rejects DNS hostnames, unbracketed IPv6 literals, and `%zone` scope suffixes.
//
// Example:
//   raw = "127.0.0.1:8080", rule = EndpointPortRule.NonZeroOnly
//   returns: ParsedEndpoint { canonical: "127.0.0.1:8080", host: "127.0.0.1", port: 8080 }, ok = true
fn parse_numeric_endpoint(raw: const u8[:], rule: EndpointPortRule) -> ParsedEndpoint, bool {
    var out = ParsedEndpoint { .. };
    guard raw.len >= 3 && raw.len <= 56 && !raw.contains_byte('%') else { return out, false; }
    if raw[0] == '[' {
        return parse_bracketed_ipv6_endpoint(raw, rule);
    }
    let host_part, port_part, has_colon = raw.split_once_byte(':');
    guard has_colon && !port_part.contains_byte(':') else { return out, false; }
    guard parse_strict_ipv4(host_part) else { return out, false; }
    let port, ok_port = parse_endpoint_port(port_part, rule);
    guard ok_port else { return out, false; }
    guard out.host.try_set(host_part) else { return out, false; }
    guard out.canonical.text.try_set(host_part) else { return out, false; }
    guard out.canonical.text.try_push(':') else { return out, false; }
    core::format_u32_dec(port, out.canonical.text);
    out.port = port;
    return out, true;
}

// Parses a strict numeric socket address into a canonical `Address` value.
//
// Example:
//   raw = "127.0.0.1:443"
//   returns: Address { text: "127.0.0.1:443" }, ok = true
fn parse_address(raw: const u8[:]) -> Address, bool {
    let ep, ok = parse_numeric_endpoint(raw, EndpointPortRule.AllowZero);
    guard ok else { return Address { .. }, false; }
    return ep.canonical, true;
}

// ---- HostLoop Internal Slot, Coalescing Byte Pool & Staging State ----------

enum LoopRunState {
    Idle,
    Running,
    Draining,
}

enum AdapterSlotState {
    Free,
    PendingConnectFail,
    Connecting,
    Open,
    Closing,
}

struct FreeByteRun {
    off: u32 = 0,
    cap: u32 = 0,
}

struct ListenerEntry {
    host_link: core::IoLink = core::IoLink { .. },
    host_text: u8[..46]     = [],
    id:        u32          = 0,
    port:      u16          = 0,
    tag:       u16          = 0,
    active:    bool         = false,
}

struct AdapterSlot {
    host_link:           core::IoLink     = core::IoLink { .. },
    peer_addr:           Address          = Address { .. },
    tx_head:             i64              = 0,
    tx_len:              i64              = 0,
    paused_rx_len:       i64              = 0,
    max_refused:         i64              = 0,
    connect_deadline_ms: i64              = 0,
    ready_pass:          u64              = 0,
    writable_pass:       u64              = 0,
    unpause_pass:        u64              = 0,
    tx_off:              u32              = 0,
    tx_cap:              u32              = 0,
    paused_rx_off:       u32              = 0,
    paused_rx_cap:       u32              = 0,
    gen:                 u32              = 1,
    user:                u32              = 0,
    listener:            Listener         = Listener { .. },
    tag:                 u16              = 0,
    state:               AdapterSlotState = AdapterSlotState.Free,
    close_why:           CloseReason      = CloseReason.Local,
    in_use:              bool             = false,
    has_tx_buf:          bool             = false,
    has_paused_rx:       bool             = false,
    has_connect_tmo:     bool             = false,
    pending_opened:      bool             = false,
    rx_held_for_open:    bool             = false,
    user_rx_paused:      bool             = false,
    paused_eof_pending:  bool             = false,
    peer_eof_seen:       bool             = false,
    keep_open_on_eof:    bool             = false,
    local_write_shut:    bool             = false,
    write_shut_sent:     bool             = false,
    writable_episode:    bool             = false,
    pending_writable:    bool             = false,
    ready_to_close:      bool             = false,
    delivering_closed:   bool             = false,
}

struct RawHostEvent {
    kind:     core::LinkEventKind = core::LinkEventKind.Data,
    link:     core::IoLink        = core::IoLink { .. },
    listener: core::IoLink        = core::IoLink { .. },
    tag:      u64                 = 0,
    data_off: u32                 = 0,
    data_len: u32                 = 0,
}

root struct PollBatch {
    events: RawHostEvent[>..] = [],
    bytes:  u8[>..]           = [],
}

fn core::on_link_event(batch: goose_io::PollBatch&, _host: net::Host&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Timer || ev.kind == core::LinkEventKind.Wake ||
       ev.kind == core::LinkEventKind.Pump {
        return;
    }
    var item = goose_io::RawHostEvent {
        kind:     ev.kind,
        link:     ev.link,
        listener: ev.listener,
        tag:      ev.tag,
        ..
    };
    if ev.kind == core::LinkEventKind.Data && ev.data.len > 0 {
        let start = batch.bytes.len;
        batch.bytes.append(ev.data);
        item.data_off = start as u32;
        item.data_len = ev.data.len as u32;
    }
    batch.events.push(item);
}

const DEFAULT_HOST_LOOP_DRIVER_CFG: net_internal::TransportDriverConfig = net_internal::TransportDriverConfig {
    active_kind: net_internal::TransportDriverKind.Standard,
    is_probed:   true,
    ..
};

root struct HostLoop {
    host:                  net::Host          = net::new_host(DEFAULT_HOST_LOOP_DRIVER_CFG),
    out_bytes:             u8[>..]            = [],
    out_free_runs:         FreeByteRun[>..<]  = [],
    slots:                 AdapterSlot[>..]   = [],
    free_slots:            u32[>..<]          = [],
    host_to_adapter:       i32[>..]           = [],
    listeners:             ListenerEntry[>..] = [],
    last_now_ns:           u64                = 0,
    last_now_ms:           i64                = 0,
    next_periodic_tick_ms: i64                = 0,
    user_tick_ms:          i64                = 0,
    grace_deadline_ms:     i64                = 0,
    pass_seq:              u64                = 0,
    active_slot_count:     i64                = 0,
    next_listener_id:      u32                = 1,
    run_state:             LoopRunState       = LoopRunState.Idle,
    has_user_tick:         bool               = false,
    has_grace_deadline:    bool               = false,
}

// ---- Coalescing Outbound Byte Pool Helpers ---------------------------------

fn pool_alloc_run(io: HostLoop&, min_cap: i64) -> u32, u32 {
    let cap = max(next_pow2(min_cap), HOST_LOOP_MIN_POOL_ALLOC);
    for k in io.out_free_runs.len {
        let run_cap = io.out_free_runs[k].cap as i64;
        if run_cap >= cap {
            let alloc_off = io.out_free_runs[k].off;
            let rem_cap = core::sub_sat_i64(run_cap, cap);
            if rem_cap >= HOST_LOOP_MIN_POOL_ALLOC {
                io.out_free_runs[k].off = (core::add_sat_u64(alloc_off, cap as u64)) as u32;
                io.out_free_runs[k].cap = rem_cap as u32;
                return alloc_off, cap as u32;
            }
            let full_cap = io.out_free_runs[k].cap;
            let _ = swap_remove(io.out_free_runs, k);
            return alloc_off, full_cap;
        }
    }
    let off = io.out_bytes.len as u32;
    push_n(io.out_bytes, 0 as u8, cap);
    return off, cap as u32;
}

fn pool_free_run(io: HostLoop&, off: u32, cap: u32) {
    guard cap > 0 else { return; }
    let end = (core::add_sat_u64(off, cap)) as u32;
    for k in io.out_free_runs.len {
        let r_off = io.out_free_runs[k].off;
        let r_cap = io.out_free_runs[k].cap;
        let r_end = (core::add_sat_u64(r_off, r_cap)) as u32;
        if r_end == off {
            io.out_free_runs[k].cap = (core::add_sat_u64(r_cap, cap)) as u32;
            return;
        }
        if end == r_off {
            io.out_free_runs[k].off = off;
            io.out_free_runs[k].cap = (core::add_sat_u64(r_cap, cap)) as u32;
            return;
        }
    }
    io.out_free_runs.push(FreeByteRun { off: off, cap: cap });
}

fn pool_realloc_run(
    io:          HostLoop&,
    old_off:     u32,
    old_cap:     u32,
    used_len:    i64,
    min_new_cap: i64,
) -> u32, u32 {
    let new_off, new_cap = pool_alloc_run(io, min_new_cap);
    if used_len > 0 {
        let src = old_off as i64;
        let dst = new_off as i64;
        io.out_bytes[dst..core::add_sat_i64(dst, used_len)].move_from(
            io.out_bytes[src..core::add_sat_i64(src, used_len)],
        );
    }
    pool_free_run(io, old_off, old_cap);
    return new_off, new_cap;
}

// ---- Clock, Lifecycle & Handle Lookup Helpers ------------------------------

fn now_ms(io: HostLoop&) -> i64 {
    let inst = core::monotonic_now();
    io.last_now_ns = max(io.last_now_ns, inst.nanos);
    let now_inst = core::MonotonicInstant { nanos: io.last_now_ns };
    let ms = core::as_millis(core::duration_since(now_inst, core::MonotonicInstant { nanos: 0 }));
    io.last_now_ms = max(io.last_now_ms, ms);
    return io.last_now_ms;
}

inline fn next_slot_gen(cur: u32) -> u32 {
    return if cur >= MAX_GEN_VALUE { 1 } else { core::add_sat_u64(cur, 1) as u32 };
}

inline fn slot_link_handle(io: const HostLoop&, idx: i64) -> Link {
    return Link { slot: idx as u32, gen: io.slots[idx].gen };
}

inline fn match_live_slot(io: const HostLoop&, link: Link) -> i64, bool {
    guard link.gen != 0 else { return -1, false; }
    let idx = link.slot as i64;
    guard idx >= 0 && idx < io.slots.len else { return -1, false; }
    guard io.slots[idx].in_use && io.slots[idx].gen == link.gen else { return -1, false; }
    return idx, true;
}

fn bind_host_link(io: HostLoop&, slot_idx: i64, h_link: core::IoLink) {
    io.slots[slot_idx].host_link = h_link;
    guard core::io_link_is_valid(h_link) else { return; }
    let h_slot = core::io_link_slot(h_link);
    guard h_slot >= 0 else { return; }
    if h_slot >= io.host_to_adapter.len {
        let add_n = core::add_sat_i64(core::sub_sat_i64(h_slot, io.host_to_adapter.len), 1);
        push_n(io.host_to_adapter, -1 as i32, add_n);
    }
    io.host_to_adapter[h_slot] = slot_idx as i32;
}

fn unbind_host_link(io: HostLoop&, slot_idx: i64) {
    let h_link = io.slots[slot_idx].host_link;
    if core::io_link_is_valid(h_link) {
        let h_slot = core::io_link_slot(h_link);
        if h_slot >= 0 && h_slot < io.host_to_adapter.len &&
           io.host_to_adapter[h_slot] == (slot_idx as i32) {
            io.host_to_adapter[h_slot] = -1;
        }
    }
    io.slots[slot_idx].host_link = core::IoLink { .. };
}

inline fn match_host_link_slot(io: const HostLoop&, h_link: core::IoLink) -> i64, bool {
    guard core::io_link_is_valid(h_link) else { return -1, false; }
    let h_slot = core::io_link_slot(h_link);
    guard h_slot >= 0 && h_slot < io.host_to_adapter.len else { return -1, false; }
    let idx = io.host_to_adapter[h_slot] as i64;
    guard idx >= 0 && idx < io.slots.len else { return -1, false; }
    guard io.slots[idx].in_use && io.slots[idx].host_link.raw == h_link.raw else { return -1, false; }
    return idx, true;
}

fn alloc_adapter_slot(io: HostLoop&, tag: u16, state: AdapterSlotState) -> i64 {
    var idx: i64 = -1;
    var gen: u32 = 1;
    if io.free_slots.len > 0 {
        let top = core::sub_sat_i64(io.free_slots.len, 1);
        idx = io.free_slots[top];
        io.free_slots.resize(top);
        gen = io.slots[idx].gen;
        if gen == 0 {
            gen = 1;
        }
    } else {
        idx = io.slots.len;
        io.slots.push(AdapterSlot { .. });
    }
    io.slots[idx] = AdapterSlot {
        gen:    gen,
        tag:    tag,
        state:  state,
        in_use: true,
        ..
    };
    io.active_slot_count = core::add_sat_i64(io.active_slot_count, 1);
    return idx;
}

fn free_slot_buffers(io: HostLoop&, idx: i64) {
    if io.slots[idx].has_tx_buf {
        pool_free_run(io, io.slots[idx].tx_off, io.slots[idx].tx_cap);
        io.slots[idx].tx_off = 0;
        io.slots[idx].tx_cap = 0;
        io.slots[idx].has_tx_buf = false;
    }
    io.slots[idx].tx_head = 0;
    io.slots[idx].tx_len = 0;
    if io.slots[idx].has_paused_rx {
        pool_free_run(io, io.slots[idx].paused_rx_off, io.slots[idx].paused_rx_cap);
        io.slots[idx].paused_rx_off = 0;
        io.slots[idx].paused_rx_cap = 0;
        io.slots[idx].has_paused_rx = false;
    }
    io.slots[idx].paused_rx_len = 0;
}

fn finalize_closed_slot(io: HostLoop&, idx: i64) {
    guard idx >= 0 && idx < io.slots.len && io.slots[idx].in_use else { return; }
    if core::io_link_is_valid(io.slots[idx].host_link) {
        let _ = net::link_close(io.host, io.slots[idx].host_link);
    }
    unbind_host_link(io, idx);
    free_slot_buffers(io, idx);
    let next_g = next_slot_gen(io.slots[idx].gen);
    io.slots[idx] = AdapterSlot { gen: next_g, .. };
    io.free_slots.push(idx as u32);
    if io.active_slot_count > 0 {
        io.active_slot_count = core::sub_sat_i64(io.active_slot_count, 1);
    }
}

fn reset_loop_session(io: HostLoop&) {
    for i in io.slots.len {
        if io.slots[i].in_use {
            finalize_closed_slot(io, i);
        }
    }
    stop_all_active_listeners(io);
    let _ = net::link_cancel_timer(io.host, HOST_LOOP_TIMER_ID);
    io.out_bytes.clear();
    io.out_free_runs.clear();
    io.active_slot_count = 0;
    io.has_user_tick = false;
    io.has_grace_deadline = false;
    io.run_state = LoopRunState.Idle;
}

// Releases all links, listeners, and OS descriptors owned by `io`.
fn close_host_loop(io: HostLoop&) {
    reset_loop_session(io);
    if io.host.is_open {
        net::close_host(io.host);
    }
}

// ---- Outbound Queue & Episode-Based Writable Tracking ----------------------

inline fn slot_queued_bytes(slot: const AdapterSlot&) -> i64 {
    guard slot.has_tx_buf && slot.tx_len > slot.tx_head else { return 0; }
    return core::sub_sat_i64(slot.tx_len, slot.tx_head);
}

inline fn calc_slot_send_room(slot: const AdapterSlot&) -> i64 {
    guard slot.in_use && slot.state == AdapterSlotState.Open && !slot.local_write_shut else {
        return 0;
    }
    return core::sub_sat_i64(HOST_LOOP_MAX_SEND, slot_queued_bytes(slot));
}

fn record_refused_send(slot: AdapterSlot&, attempted_len: i64) {
    slot.pending_writable = false;
    if !slot.writable_episode {
        slot.writable_episode = true;
        slot.max_refused = attempted_len;
    } else {
        slot.max_refused = max(slot.max_refused, attempted_len);
    }
}

fn check_writable_episode(io: HostLoop&, idx: i64) {
    let room = calc_slot_send_room(io.slots[idx]);
    guard io.slots[idx].writable_episode && room >= io.slots[idx].max_refused else { return; }
    io.slots[idx].writable_episode = false;
    io.slots[idx].max_refused = 0;
    io.slots[idx].pending_writable = true;
    io.slots[idx].writable_pass = core::add_sat_u64(io.pass_seq, 1);
}

fn compact_slot_tx_in_place(io: HostLoop&, idx: i64) {
    guard io.slots[idx].tx_head > 0 else { return; }
    let unread = slot_queued_bytes(io.slots[idx]);
    if unread > 0 {
        let base = io.slots[idx].tx_off as i64;
        let src_s = core::add_sat_i64(base, io.slots[idx].tx_head);
        let src_e = core::add_sat_i64(base, io.slots[idx].tx_len);
        io.out_bytes[base..core::add_sat_i64(base, unread)].move_from(io.out_bytes[src_s..src_e]);
    }
    io.slots[idx].tx_head = 0;
    io.slots[idx].tx_len = unread;
}

fn enqueue_slot_tx(io: HostLoop&, idx: i64, data: const u8[:]) {
    guard data.len > 0 else { return; }
    if !io.slots[idx].has_tx_buf {
        let init_cap = min(max(next_pow2(data.len), HOST_LOOP_MIN_POOL_ALLOC), HOST_LOOP_MAX_SEND);
        let off, cap = pool_alloc_run(io, init_cap);
        io.slots[idx].tx_off = off;
        io.slots[idx].tx_cap = cap;
        io.slots[idx].has_tx_buf = true;
        io.slots[idx].tx_head = 0;
        io.slots[idx].tx_len = 0;
    } else if core::add_sat_i64(io.slots[idx].tx_len, data.len) > io.slots[idx].tx_cap {
        compact_slot_tx_in_place(io, idx);
        let needed = core::add_sat_i64(io.slots[idx].tx_len, data.len);
        if needed > io.slots[idx].tx_cap {
            let target_cap = min(max(next_pow2(needed), HOST_LOOP_MIN_POOL_ALLOC), HOST_LOOP_MAX_SEND);
            let new_off, new_cap = pool_realloc_run(
                io, io.slots[idx].tx_off, io.slots[idx].tx_cap, io.slots[idx].tx_len, target_cap,
            );
            io.slots[idx].tx_off = new_off;
            io.slots[idx].tx_cap = new_cap;
        }
    }
    let base = io.slots[idx].tx_off as i64;
    let dst_off = core::add_sat_i64(base, io.slots[idx].tx_len);
    let dst_end = core::add_sat_i64(dst_off, data.len);
    io.out_bytes[dst_off..dst_end].copy_into(data);
    io.slots[idx].tx_len = core::add_sat_i64(io.slots[idx].tx_len, data.len);
}

fn mark_broken_pipe_close(io: HostLoop&, idx: i64) {
    if core::io_link_is_valid(io.slots[idx].host_link) {
        let _ = net::link_close(io.host, io.slots[idx].host_link);
    }
    unbind_host_link(io, idx);
    free_slot_buffers(io, idx);
    if io.slots[idx].state != AdapterSlotState.Closing {
        io.slots[idx].state = AdapterSlotState.Closing;
        io.slots[idx].close_why = CloseReason.PeerReset;
    }
    io.slots[idx].pending_writable = false;
    io.slots[idx].writable_episode = false;
    io.slots[idx].ready_to_close = true;
    io.slots[idx].ready_pass = core::add_sat_u64(io.pass_seq, 1);
}

fn flush_slot_tx(io: HostLoop&, idx: i64) -> bool {
    while io.slots[idx].has_tx_buf && io.slots[idx].tx_head < io.slots[idx].tx_len {
        let h_link = io.slots[idx].host_link;
        guard core::io_link_is_valid(h_link) else {
            free_slot_buffers(io, idx);
            return false;
        }
        let base = io.slots[idx].tx_off as i64;
        let abs_head = core::add_sat_i64(base, io.slots[idx].tx_head);
        let abs_end = core::add_sat_i64(base, io.slots[idx].tx_len);
        let sent, err = net::link_send(io.host, h_link, io.out_bytes[abs_head..abs_end]);
        if sent > 0 {
            io.slots[idx].tx_head = core::add_sat_i64(io.slots[idx].tx_head, sent);
        }
        if err == core::IoError.Closed || err == core::IoError.InvalidArgument {
            mark_broken_pipe_close(io, idx);
            return false;
        }
        if err != core::IoError.None {
            break;
        }
    }
    if io.slots[idx].has_tx_buf && io.slots[idx].tx_head >= io.slots[idx].tx_len {
        pool_free_run(io, io.slots[idx].tx_off, io.slots[idx].tx_cap);
        io.slots[idx].tx_off = 0;
        io.slots[idx].tx_cap = 0;
        io.slots[idx].has_tx_buf = false;
        io.slots[idx].tx_head = 0;
        io.slots[idx].tx_len = 0;
    }
    return !io.slots[idx].has_tx_buf;
}

fn send_immediate_or_queue(io: HostLoop&, idx: i64, chunk: const u8[:]) -> bool {
    guard chunk.len > 0 else { return true; }
    if slot_queued_bytes(io.slots[idx]) > 0 {
        enqueue_slot_tx(io, idx, chunk);
        return true;
    }
    let sent, err = net::link_send(io.host, io.slots[idx].host_link, chunk);
    if err == core::IoError.Closed || err == core::IoError.InvalidArgument {
        mark_broken_pipe_close(io, idx);
        return false;
    }
    let written = max(0, sent as i64);
    if written < chunk.len {
        enqueue_slot_tx(io, idx, chunk[written..]);
    }
    return true;
}

fn stash_paused_rx(io: HostLoop&, idx: i64, data: const u8[:]) {
    guard data.len > 0 else { return; }
    let cur_len = io.slots[idx].paused_rx_len;
    let needed = core::add_sat_i64(cur_len, data.len);
    if !io.slots[idx].has_paused_rx {
        let off, cap = pool_alloc_run(io, needed);
        io.slots[idx].paused_rx_off = off;
        io.slots[idx].paused_rx_cap = cap;
        io.slots[idx].has_paused_rx = true;
    } else if needed > io.slots[idx].paused_rx_cap {
        let new_off, new_cap = pool_realloc_run(
            io, io.slots[idx].paused_rx_off, io.slots[idx].paused_rx_cap, cur_len, needed,
        );
        io.slots[idx].paused_rx_off = new_off;
        io.slots[idx].paused_rx_cap = new_cap;
    }
    let base = io.slots[idx].paused_rx_off as i64;
    let dst_s = core::add_sat_i64(base, cur_len);
    let dst_e = core::add_sat_i64(base, needed);
    io.out_bytes[dst_s..dst_e].copy_into(data);
    io.slots[idx].paused_rx_len = needed;
}

// ---- Core & Optional Operations on `HostLoop` ------------------------------

fn has_conflicting_listener_port(io: const HostLoop&, host_text: const u8[:], port: u16) -> bool {
    guard port != 0 else { return false; }
    for i in io.listeners.len {
        if io.listeners[i].active && io.listeners[i].port == port {
            let existing = io.listeners[i].host_text[..];
            if existing == host_text || existing == "0.0.0.0" || host_text == "0.0.0.0" {
                return true;
            }
        }
    }
    return false;
}

fn classify_listen_failure(ep: const ParsedEndpoint&, err: core::IoError) -> ListenError {
    if err == core::IoError.BufferFull || err == core::IoError.LimitExceeded {
        return ListenError { kind: ListenErrorKind.NoResources, code: 0 };
    }
    if err == core::IoError.InvalidArgument {
        return ListenError { kind: ListenErrorKind.BadAddress, code: 0 };
    }
    if !ep.is_ipv6 && ep.port >= MIN_UNPRIVILEGED_PORT &&
       (ep.host[..] == "127.0.0.1" || ep.host[..] == "0.0.0.0") {
        return ListenError { kind: ListenErrorKind.AddressInUse, code: 0 };
    }
    return ListenError { kind: ListenErrorKind.Other, code: 0 };
}

fn listen(io: HostLoop&, address: const u8[:], tag: u16) -> Listener, ListenError {
    let ep, ok = parse_numeric_endpoint(address, EndpointPortRule.AllowZero);
    guard ok else {
        return Listener { .. }, ListenError { kind: ListenErrorKind.BadAddress, code: 0 };
    }
    guard io.run_state != LoopRunState.Draining && io.host.is_open else {
        return Listener { .. }, ListenError { kind: ListenErrorKind.Other, code: 0 };
    }
    let _ = now_ms(io);
    if has_conflicting_listener_port(io, ep.host[..], ep.port) {
        return Listener { .. }, ListenError { kind: ListenErrorKind.AddressInUse, code: 0 };
    }
    let id = if io.next_listener_id == 0 { 1 as u32 } else { io.next_listener_id };
    let h_link, err = net::link_listen(
        io.host,
        core::ConnectAddr.Tcp { host: ep.host[..], port: ep.port },
        HOST_LOOP_OWNER_ID,
        id,
        HOST_LOOP_BACKLOG,
    );
    guard err == core::IoError.None && core::io_link_is_valid(h_link) else {
        return Listener { .. }, classify_listen_failure(ep, err);
    }
    io.next_listener_id = core::add_sat_u64(id, 1) as u32;
    let bound_port = net::link_local_port(io.host, h_link);
    let final_port = if bound_port != 0 { bound_port } else { ep.port };
    var entry = ListenerEntry {
        host_link: h_link,
        id:        id,
        port:      final_port,
        tag:       tag,
        active:    true,
        ..
    };
    let _ = entry.host_text.try_set(ep.host[..]);
    io.listeners.push(entry);
    return Listener { id: id }, ListenError { kind: ListenErrorKind.None, code: 0 };
}

fn listener_port(io: const HostLoop&, listener: Listener) -> u16 {
    guard is_listener(listener) else { return 0; }
    for i in io.listeners.len {
        if io.listeners[i].id == listener.id {
            guard io.listeners[i].active else { return 0; }
            return io.listeners[i].port;
        }
    }
    return 0;
}

fn stop_listening(io: HostLoop&, listener: Listener) {
    guard is_listener(listener) else { return; }
    for i in io.listeners.len {
        if io.listeners[i].id == listener.id && io.listeners[i].active {
            if core::io_link_is_valid(io.listeners[i].host_link) {
                let _ = net::link_close(io.host, io.listeners[i].host_link);
            }
            io.listeners[i].active = false;
            io.listeners[i].host_link = core::IoLink { .. };
            return;
        }
    }
}

fn queue_deferred_connect_fail(io: HostLoop&, idx: i64, kind: ConnectFailure) -> Link {
    io.slots[idx].state = AdapterSlotState.PendingConnectFail;
    io.slots[idx].close_why = CloseReason.ConnectFailed { kind: kind };
    io.slots[idx].ready_pass = core::add_sat_u64(io.pass_seq, 1);
    return slot_link_handle(io, idx);
}

fn dial(io: HostLoop&, address: const u8[:], tag: u16, connect_ms: i64) -> Link {
    let _ = now_ms(io);
    let idx = alloc_adapter_slot(io, tag, AdapterSlotState.Connecting);
    let ep, ok = parse_numeric_endpoint(address, EndpointPortRule.NonZeroOnly);
    if !ok {
        return queue_deferred_connect_fail(io, idx, ConnectFailure.BadAddress);
    }
    io.slots[idx].peer_addr = ep.canonical;
    if io.run_state == LoopRunState.Draining || !io.host.is_open {
        return queue_deferred_connect_fail(io, idx, ConnectFailure.Other);
    }
    let h_link, st = net::link_connect(
        io.host,
        core::ConnectAddr.Tcp { host: ep.host[..], port: ep.port },
        HOST_LOOP_OWNER_ID,
        idx as u64,
    );
    if st == core::ConnectStatus.InvalidArgument {
        return queue_deferred_connect_fail(io, idx, ConnectFailure.BadAddress);
    }
    if st == core::ConnectStatus.Failed || !core::io_link_is_valid(h_link) {
        let fail_kind = if ep.is_ipv6 { ConnectFailure.Other } else { ConnectFailure.Refused };
        return queue_deferred_connect_fail(io, idx, fail_kind);
    }
    bind_host_link(io, idx, h_link);
    if st == core::ConnectStatus.Connected {
        let _ = net::link_set_rx_paused(io.host, h_link, true);
        io.slots[idx].rx_held_for_open = true;
        io.slots[idx].pending_opened = true;
        io.slots[idx].ready_pass = core::add_sat_u64(io.pass_seq, 1);
    } else if connect_ms > 0 {
        io.slots[idx].has_connect_tmo = true;
        io.slots[idx].connect_deadline_ms = core::add_sat_i64(io.last_now_ms, connect_ms);
    }
    return slot_link_handle(io, idx);
}

// Opens an in-memory bidirectional virtual link pair scheduled via deferred `Opened` events.
fn open_virtual_pair(io: HostLoop&, tag_a: u16, tag_b: u16) -> Link, Link, bool {
    guard io.run_state != LoopRunState.Draining && io.host.is_open else {
        return Link { .. }, Link { .. }, false;
    }
    let _ = now_ms(io);
    let ha, hb, ok = net::open_virtual_pair(
        io.host, HOST_LOOP_OWNER_ID, HOST_LOOP_OWNER_ID, 0, 0,
    );
    guard ok else { return Link { .. }, Link { .. }, false; }
    let idx_a = alloc_adapter_slot(io, tag_a, AdapterSlotState.Connecting);
    let idx_b = alloc_adapter_slot(io, tag_b, AdapterSlotState.Connecting);
    bind_host_link(io, idx_a, ha);
    bind_host_link(io, idx_b, hb);
    let _ = net::link_set_rx_paused(io.host, ha, true);
    let _ = net::link_set_rx_paused(io.host, hb, true);
    let next_p = core::add_sat_u64(io.pass_seq, 1);
    io.slots[idx_a].rx_held_for_open = true;
    io.slots[idx_a].pending_opened = true;
    io.slots[idx_a].ready_pass = next_p;
    io.slots[idx_b].rx_held_for_open = true;
    io.slots[idx_b].pending_opened = true;
    io.slots[idx_b].ready_pass = next_p;
    return slot_link_handle(io, idx_a), slot_link_handle(io, idx_b), true;
}

inline fn max_send(_io: const HostLoop&) -> i64 {
    return HOST_LOOP_MAX_SEND;
}

fn send_room(io: const HostLoop&, link: Link) -> i64 {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return 0; }
    return calc_slot_send_room(io.slots[idx]);
}

fn precheck_send(io: HostLoop&, link: Link, total_len: i64) -> i64, SendStatus, bool {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else {
        return -1, SendStatus.Closed, false;
    }
    let st = io.slots[idx].state;
    if st == AdapterSlotState.Closing || io.slots[idx].local_write_shut {
        return -1, SendStatus.Closed, false;
    }
    if st == AdapterSlotState.Connecting || st == AdapterSlotState.PendingConnectFail {
        return -1, SendStatus.NotOpen, false;
    }
    if total_len <= 0 {
        return idx, SendStatus.Sent, false;
    }
    if total_len > HOST_LOOP_MAX_SEND {
        return -1, SendStatus.TooLarge, false;
    }
    let room = calc_slot_send_room(io.slots[idx]);
    if total_len > room {
        record_refused_send(io.slots[idx], total_len);
        return -1, SendStatus.Full, false;
    }
    return idx, SendStatus.Sent, true;
}

fn send(io: HostLoop&, link: Link, bytes: const u8[:]) -> SendStatus {
    let idx, status, proceed = precheck_send(io, link, bytes.len);
    guard proceed else { return status; }
    if send_immediate_or_queue(io, idx, bytes) && slot_queued_bytes(io.slots[idx]) > 0 {
        let _ = flush_slot_tx(io, idx);
        check_writable_episode(io, idx);
    }
    return SendStatus.Sent;
}

fn send2(io: HostLoop&, link: Link, head: const u8[:], tail: const u8[:]) -> SendStatus {
    let total = core::add_sat_i64(head.len, tail.len);
    let idx, status, proceed = precheck_send(io, link, total);
    guard proceed else { return status; }
    if send_immediate_or_queue(io, idx, head) {
        if send_immediate_or_queue(io, idx, tail) && slot_queued_bytes(io.slots[idx]) > 0 {
            let _ = flush_slot_tx(io, idx);
            check_writable_episode(io, idx);
        }
    }
    return SendStatus.Sent;
}

fn pause_reading(io: HostLoop&, link: Link, paused: bool) {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return; }
    let st = io.slots[idx].state;
    guard st == AdapterSlotState.Connecting || st == AdapterSlotState.Open else { return; }
    guard io.slots[idx].user_rx_paused != paused else { return; }
    io.slots[idx].user_rx_paused = paused;
    let h_link = io.slots[idx].host_link;
    if paused {
        if core::io_link_is_valid(h_link) {
            let _ = net::link_set_rx_paused(io.host, h_link, true);
        }
        return;
    }
    if st == AdapterSlotState.Open && !io.slots[idx].rx_held_for_open &&
       !io.slots[idx].paused_eof_pending && core::io_link_is_valid(h_link) {
        let _ = net::link_set_rx_paused(io.host, h_link, false);
    }
    if io.slots[idx].has_paused_rx || io.slots[idx].paused_eof_pending {
        io.slots[idx].unpause_pass = core::add_sat_u64(io.pass_seq, 1);
    }
}

fn set_keep_open_on_eof(io: HostLoop&, link: Link, keep_open: bool) {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return; }
    let st = io.slots[idx].state;
    guard st == AdapterSlotState.Connecting || st == AdapterSlotState.Open else { return; }
    io.slots[idx].keep_open_on_eof = keep_open;
}

fn complete_write_shutdown(io: HostLoop&, idx: i64, pass_target: u64) {
    let h_link = io.slots[idx].host_link;
    if core::io_link_is_valid(h_link) && !io.slots[idx].write_shut_sent {
        let _ = net::link_shutdown_write(io.host, h_link);
        io.slots[idx].write_shut_sent = true;
    }
    if io.slots[idx].peer_eof_seen && io.slots[idx].state == AdapterSlotState.Open {
        if core::io_link_is_valid(h_link) {
            let _ = net::link_close(io.host, h_link);
        }
        unbind_host_link(io, idx);
        io.slots[idx].state = AdapterSlotState.Closing;
        io.slots[idx].close_why = CloseReason.PeerClosed;
        io.slots[idx].ready_to_close = true;
        io.slots[idx].ready_pass = pass_target;
    }
}

fn shutdown_write(io: HostLoop&, link: Link) {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return; }
    guard io.slots[idx].state == AdapterSlotState.Open && !io.slots[idx].local_write_shut else {
        return;
    }
    io.slots[idx].local_write_shut = true;
    io.slots[idx].pending_writable = false;
    io.slots[idx].writable_episode = false;
    if flush_slot_tx(io, idx) && io.slots[idx].state == AdapterSlotState.Open {
        complete_write_shutdown(io, idx, core::add_sat_u64(io.pass_seq, 1));
    }
}

fn begin_graceful_slot_close(io: HostLoop&, idx: i64, why: CloseReason, pass_target: u64) {
    io.slots[idx].pending_opened = false;
    io.slots[idx].pending_writable = false;
    io.slots[idx].writable_episode = false;
    io.slots[idx].paused_eof_pending = false;
    if io.slots[idx].has_paused_rx {
        pool_free_run(io, io.slots[idx].paused_rx_off, io.slots[idx].paused_rx_cap);
        io.slots[idx].paused_rx_off = 0;
        io.slots[idx].paused_rx_cap = 0;
        io.slots[idx].has_paused_rx = false;
        io.slots[idx].paused_rx_len = 0;
    }
    let prev_state = io.slots[idx].state;
    io.slots[idx].state = AdapterSlotState.Closing;
    io.slots[idx].close_why = why;
    let h_link = io.slots[idx].host_link;
    if prev_state != AdapterSlotState.Open {
        if core::io_link_is_valid(h_link) {
            let _ = net::link_close(io.host, h_link);
        }
        unbind_host_link(io, idx);
        io.slots[idx].ready_to_close = true;
        io.slots[idx].ready_pass = pass_target;
        return;
    }
    if core::io_link_is_valid(h_link) {
        let _ = net::link_set_rx_paused(io.host, h_link, true);
    }
    if flush_slot_tx(io, idx) {
        if core::io_link_is_valid(io.slots[idx].host_link) {
            let _ = net::link_close(io.host, io.slots[idx].host_link);
        }
        unbind_host_link(io, idx);
        io.slots[idx].ready_to_close = true;
        io.slots[idx].ready_pass = pass_target;
    }
}

fn close(io: HostLoop&, link: Link) {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return; }
    if io.slots[idx].state == AdapterSlotState.Closing {
        return;
    }
    begin_graceful_slot_close(io, idx, CloseReason.Local, core::add_sat_u64(io.pass_seq, 1));
}

fn reset(io: HostLoop&, link: Link) {
    let idx, ok = match_live_slot(io, link);
    guard ok && !io.slots[idx].delivering_closed else { return; }
    if io.slots[idx].state == AdapterSlotState.Closing && io.slots[idx].ready_to_close {
        return;
    }
    let h_link = io.slots[idx].host_link;
    if core::io_link_is_valid(h_link) {
        let _ = net::link_abort(io.host, h_link);
    }
    unbind_host_link(io, idx);
    free_slot_buffers(io, idx);
    io.slots[idx].pending_opened = false;
    io.slots[idx].pending_writable = false;
    io.slots[idx].writable_episode = false;
    io.slots[idx].paused_eof_pending = false;
    io.slots[idx].state = AdapterSlotState.Closing;
    io.slots[idx].close_why = CloseReason.Local;
    io.slots[idx].ready_to_close = true;
    io.slots[idx].ready_pass = core::add_sat_u64(io.pass_seq, 1);
}

fn set_user(io: HostLoop&, link: Link, user_val: u32) {
    let idx, ok = match_live_slot(io, link);
    guard ok else { return; }
    io.slots[idx].user = user_val;
}

fn user(io: const HostLoop&, link: Link) -> u32 {
    let idx, ok = match_live_slot(io, link);
    guard ok else { return 0; }
    return io.slots[idx].user;
}

fn peer_address(io: const HostLoop&, link: Link) -> Address {
    let idx, ok = match_live_slot(io, link);
    guard ok else { return Address { .. }; }
    return io.slots[idx].peer_addr;
}

fn tick_by(io: HostLoop&, at_ms: i64) {
    let _ = now_ms(io);
    if !io.has_user_tick || at_ms < io.user_tick_ms {
        io.has_user_tick = true;
        io.user_tick_ms = at_ms;
    }
}

fn stop_all_active_listeners(io: HostLoop&) {
    for i in io.listeners.len {
        if io.listeners[i].active {
            if core::io_link_is_valid(io.listeners[i].host_link) {
                let _ = net::link_close(io.host, io.listeners[i].host_link);
            }
            io.listeners[i].active = false;
            io.listeners[i].host_link = core::IoLink { .. };
        }
    }
}

fn stop(io: HostLoop&, grace_ms: i64) {
    let cur_ms = now_ms(io);
    let clamped_grace = max(0, grace_ms);
    let deadline = core::add_sat_i64(cur_ms, clamped_grace);
    if io.run_state == LoopRunState.Draining && io.has_grace_deadline {
        io.grace_deadline_ms = min(io.grace_deadline_ms, deadline);
    } else {
        io.run_state = LoopRunState.Draining;
        io.has_grace_deadline = true;
        io.grace_deadline_ms = deadline;
    }
    stop_all_active_listeners(io);
}

inline fn draining(io: const HostLoop&) -> bool {
    return io.run_state == LoopRunState.Draining;
}

// ---- Pass Scheduling, Timeout Calculation & Event Delivery -----------------

fn slot_has_ready_work(slot: const AdapterSlot&, next_pass: u64) -> bool {
    guard slot.in_use else { return false; }
    if slot.state == AdapterSlotState.PendingConnectFail && slot.ready_pass <= next_pass {
        return true;
    }
    if slot.pending_opened && slot.ready_pass <= next_pass {
        return true;
    }
    if slot.pending_writable && slot.writable_pass <= next_pass {
        return true;
    }
    if slot.state == AdapterSlotState.Open && !slot.user_rx_paused &&
       (slot.has_paused_rx || slot.paused_eof_pending) && slot.unpause_pass <= next_pass {
        return true;
    }
    return slot.state == AdapterSlotState.Closing && slot.ready_to_close && slot.ready_pass <= next_pass;
}

fn compute_next_deadline_ms(io: const HostLoop&, cur_ms: i64) -> i64 {
    var earliest = io.next_periodic_tick_ms;
    if earliest <= cur_ms {
        return cur_ms;
    }
    if io.has_user_tick {
        earliest = min(earliest, io.user_tick_ms);
    }
    if io.run_state == LoopRunState.Draining && io.has_grace_deadline {
        earliest = min(earliest, io.grace_deadline_ms);
    }
    for i in io.slots.len {
        if io.slots[i].in_use && io.slots[i].state == AdapterSlotState.Connecting &&
           io.slots[i].has_connect_tmo {
            earliest = min(earliest, io.slots[i].connect_deadline_ms);
        }
    }
    return max(cur_ms, earliest);
}

fn compute_pass_timeout_ms(io: HostLoop&, cur_ms: i64, next_pass: u64) -> i64 {
    for i in io.slots.len {
        if slot_has_ready_work(io.slots[i], next_pass) {
            let _ = net::link_cancel_timer(io.host, HOST_LOOP_TIMER_ID);
            return 0;
        }
    }
    let deadline = compute_next_deadline_ms(io, cur_ms);
    let wait_ms = min(HOST_LOOP_TICK_PERIOD_MS, max(0, core::sub_sat_i64(deadline, cur_ms)));
    if wait_ms > 0 {
        let _ = net::link_add_timer(
            io.host, HOST_LOOP_TIMER_ID, wait_ms as u64, HOST_LOOP_OWNER_ID, 0, false, io.last_now_ns,
        );
    } else {
        let _ = net::link_cancel_timer(io.host, HOST_LOOP_TIMER_ID);
    }
    return wait_ms;
}

fn abort_all_for_grace_expiry(io: HostLoop&) {
    for i in io.slots.len {
        guard io.slots[i].in_use && !io.slots[i].delivering_closed else { continue; }
        if io.slots[i].state == AdapterSlotState.Closing && io.slots[i].ready_to_close {
            io.slots[i].ready_pass = io.pass_seq;
            continue;
        }
        if core::io_link_is_valid(io.slots[i].host_link) {
            let _ = net::link_abort(io.host, io.slots[i].host_link);
        }
        unbind_host_link(io, i);
        free_slot_buffers(io, i);
        io.slots[i].pending_opened = false;
        io.slots[i].pending_writable = false;
        io.slots[i].writable_episode = false;
        io.slots[i].paused_eof_pending = false;
        io.slots[i].state = AdapterSlotState.Closing;
        io.slots[i].close_why = CloseReason.Shutdown;
        io.slots[i].ready_to_close = true;
        io.slots[i].ready_pass = io.pass_seq;
    }
}

fn sweep_pass_deadlines(io: HostLoop&, cur_ms: i64) {
    if io.run_state == LoopRunState.Draining && io.has_grace_deadline && cur_ms >= io.grace_deadline_ms {
        abort_all_for_grace_expiry(io);
        return;
    }
    for i in io.slots.len {
        guard io.slots[i].in_use else { continue; }
        if io.slots[i].state == AdapterSlotState.PendingConnectFail && io.slots[i].ready_pass <= io.pass_seq {
            io.slots[i].state = AdapterSlotState.Closing;
            io.slots[i].ready_to_close = true;
        } else if io.slots[i].state == AdapterSlotState.Connecting &&
                  io.slots[i].has_connect_tmo &&
                  cur_ms >= io.slots[i].connect_deadline_ms {
            if core::io_link_is_valid(io.slots[i].host_link) {
                let _ = net::link_close(io.host, io.slots[i].host_link);
            }
            unbind_host_link(io, i);
            io.slots[i].pending_opened = false;
            io.slots[i].state = AdapterSlotState.Closing;
            io.slots[i].close_why = CloseReason.ConnectFailed { kind: ConnectFailure.TimedOut };
            io.slots[i].ready_to_close = true;
            io.slots[i].ready_pass = io.pass_seq;
        }
    }
}

enum PassPhase {
    DeferredSlots,
    RawEvents,
    ReadyCloses,
    PassEndPhase,
    TickPhase,
    Done,
}

enum PostEventHook {
    None,
    AfterPeerEof,
    AfterClosed,
}

struct PassCursor {
    phase:          PassPhase     = PassPhase.DeferredSlots,
    post_hook:      PostEventHook = PostEventHook.None,
    hook_slot:      i64           = -1,
    hook_gen:       u32           = 0,
    slot_cursor:    i64           = 0,
    raw_cursor:     i64           = 0,
    link_delivered: i64           = 0,
    sub_step:       i64           = 0,
}

fn find_active_listener_by_host(io: const HostLoop&, l_host: core::IoLink) -> i64, bool {
    for i in io.listeners.len {
        if io.listeners[i].active && io.listeners[i].host_link.raw == l_host.raw {
            return i, true;
        }
    }
    return -1, false;
}

fn step_deferred_slot_open(io: HostLoop&, idx: i64, cur: PassCursor&) -> Event, bool {
    guard io.slots[idx].in_use && io.slots[idx].state == AdapterSlotState.Connecting else {
        return Event.PassEnd, false;
    }
    guard io.slots[idx].pending_opened && io.slots[idx].ready_pass <= io.pass_seq else {
        return Event.PassEnd, false;
    }
    io.slots[idx].pending_opened = false;
    io.slots[idx].state = AdapterSlotState.Open;
    if io.slots[idx].rx_held_for_open {
        io.slots[idx].rx_held_for_open = false;
        if !io.slots[idx].user_rx_paused && core::io_link_is_valid(io.slots[idx].host_link) {
            let _ = net::link_set_rx_paused(io.host, io.slots[idx].host_link, false);
        }
    }
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Opened {
        link:     slot_link_handle(io, idx),
        tag:      io.slots[idx].tag,
        user:     io.slots[idx].user,
        listener: io.slots[idx].listener,
    }, true;
}

fn step_deferred_slot_unpaused_data(
    io:    HostLoop&,
    idx:   i64,
    batch: PollBatch&,
    cur:   PassCursor&,
) -> Event, bool {
    guard io.slots[idx].in_use && io.slots[idx].state == AdapterSlotState.Open else {
        return Event.PassEnd, false;
    }
    guard !io.slots[idx].user_rx_paused && io.slots[idx].unpause_pass <= io.pass_seq else {
        return Event.PassEnd, false;
    }
    guard io.slots[idx].has_paused_rx && io.slots[idx].paused_rx_len > 0 else {
        return Event.PassEnd, false;
    }
    let start = batch.bytes.len;
    let len = io.slots[idx].paused_rx_len;
    let base = io.slots[idx].paused_rx_off as i64;
    batch.bytes.append(io.out_bytes[base..core::add_sat_i64(base, len)]);
    pool_free_run(io, io.slots[idx].paused_rx_off, io.slots[idx].paused_rx_cap);
    io.slots[idx].paused_rx_off = 0;
    io.slots[idx].paused_rx_cap = 0;
    io.slots[idx].has_paused_rx = false;
    io.slots[idx].paused_rx_len = 0;
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Data {
        link:  slot_link_handle(io, idx),
        tag:   io.slots[idx].tag,
        user:  io.slots[idx].user,
        bytes: batch.bytes[start..core::add_sat_i64(start, len)],
    }, true;
}

fn prepare_slot_eof_event(io: HostLoop&, idx: i64, cur: PassCursor&) -> Event, bool {
    guard !io.slots[idx].peer_eof_seen else { return Event.PassEnd, false; }
    io.slots[idx].peer_eof_seen = true;
    cur.post_hook = PostEventHook.AfterPeerEof;
    cur.hook_slot = idx;
    cur.hook_gen = io.slots[idx].gen;
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.PeerEof {
        link: slot_link_handle(io, idx),
        tag:  io.slots[idx].tag,
        user: io.slots[idx].user,
    }, true;
}

fn step_deferred_slot_item(
    io:    HostLoop&,
    idx:   i64,
    step:  i64,
    batch: PollBatch&,
    cur:   PassCursor&,
) -> Event, bool {
    if step == 0 {
        return step_deferred_slot_open(io, idx, cur);
    }
    if step == 1 {
        return step_deferred_slot_unpaused_data(io, idx, batch, cur);
    }
    if step == 2 {
        guard io.slots[idx].in_use && io.slots[idx].state == AdapterSlotState.Open else {
            return Event.PassEnd, false;
        }
        guard !io.slots[idx].user_rx_paused &&
            io.slots[idx].unpause_pass <= io.pass_seq &&
            io.slots[idx].paused_eof_pending else {
            return Event.PassEnd, false;
        }
        io.slots[idx].paused_eof_pending = false;
        return prepare_slot_eof_event(io, idx, cur);
    }
    guard io.slots[idx].in_use && io.slots[idx].state == AdapterSlotState.Open else {
        return Event.PassEnd, false;
    }
    guard io.slots[idx].pending_writable && io.slots[idx].writable_pass <= io.pass_seq else {
        return Event.PassEnd, false;
    }
    io.slots[idx].pending_writable = false;
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Writable {
        link: slot_link_handle(io, idx),
        tag:  io.slots[idx].tag,
        user: io.slots[idx].user,
    }, true;
}

fn next_deferred_slot_event(io: HostLoop&, batch: PollBatch&, cur: PassCursor&) -> Event, bool {
    while cur.slot_cursor < io.slots.len {
        let idx = cur.slot_cursor;
        if !io.slots[idx].in_use {
            cur.slot_cursor = core::add_sat_i64(idx, 1);
            cur.sub_step = 0;
            continue;
        }
        let step = cur.sub_step;
        if step >= 3 {
            cur.slot_cursor = core::add_sat_i64(idx, 1);
            cur.sub_step = 0;
        } else {
            cur.sub_step = core::add_sat_i64(step, 1);
        }
        let ev, ok = step_deferred_slot_item(io, idx, step, batch, cur);
        if ok {
            return ev, true;
        }
    }
    cur.phase = PassPhase.RawEvents;
    cur.raw_cursor = 0;
    return Event.PassEnd, false;
}

fn step_raw_accepted(io: HostLoop&, raw: const RawHostEvent&, cur: PassCursor&) -> Event, bool {
    if io.run_state == LoopRunState.Draining {
        let _ = net::link_close(io.host, raw.link);
        return Event.PassEnd, false;
    }
    let l_idx, ok = find_active_listener_by_host(io, raw.listener);
    guard ok else {
        let _ = net::link_close(io.host, raw.link);
        return Event.PassEnd, false;
    }
    let tag = io.listeners[l_idx].tag;
    let lst = Listener { id: io.listeners[l_idx].id };
    let idx = alloc_adapter_slot(io, tag, AdapterSlotState.Open);
    io.slots[idx].listener = lst;
    bind_host_link(io, idx, raw.link);
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Opened {
        link:     slot_link_handle(io, idx),
        tag:      tag,
        user:     0,
        listener: lst,
    }, true;
}

fn step_raw_writable(io: HostLoop&, idx: i64, cur: PassCursor&) -> Event, bool {
    let st = io.slots[idx].state;
    guard st == AdapterSlotState.Open || st == AdapterSlotState.Closing else {
        return Event.PassEnd, false;
    }
    let empty = flush_slot_tx(io, idx);
    guard io.slots[idx].in_use else { return Event.PassEnd, false; }
    if io.slots[idx].state == AdapterSlotState.Closing {
        if empty && !io.slots[idx].ready_to_close {
            if core::io_link_is_valid(io.slots[idx].host_link) {
                let _ = net::link_close(io.host, io.slots[idx].host_link);
            }
            unbind_host_link(io, idx);
            io.slots[idx].ready_to_close = true;
            io.slots[idx].ready_pass = io.pass_seq;
        }
        return Event.PassEnd, false;
    }
    if io.slots[idx].local_write_shut && empty {
        complete_write_shutdown(io, idx, io.pass_seq);
        return Event.PassEnd, false;
    }
    check_writable_episode(io, idx);
    guard io.slots[idx].pending_writable else { return Event.PassEnd, false; }
    io.slots[idx].pending_writable = false;
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Writable {
        link: slot_link_handle(io, idx),
        tag:  io.slots[idx].tag,
        user: io.slots[idx].user,
    }, true;
}

fn record_raw_host_close(io: HostLoop&, idx: i64) {
    unbind_host_link(io, idx);
    free_slot_buffers(io, idx);
    let prev = io.slots[idx].state;
    let why: CloseReason = if prev == AdapterSlotState.Connecting {
        CloseReason.ConnectFailed { kind: ConnectFailure.Refused }
    } else if prev == AdapterSlotState.Closing {
        io.slots[idx].close_why
    } else if io.slots[idx].peer_eof_seen {
        CloseReason.PeerClosed
    } else {
        CloseReason.PeerReset
    };
    io.slots[idx].pending_opened = false;
    io.slots[idx].pending_writable = false;
    io.slots[idx].writable_episode = false;
    io.slots[idx].state = AdapterSlotState.Closing;
    io.slots[idx].close_why = why;
    io.slots[idx].ready_to_close = true;
    io.slots[idx].ready_pass = io.pass_seq;
}

fn step_raw_data(
    io:    HostLoop&,
    batch: const PollBatch&,
    idx:   i64,
    raw:   const RawHostEvent&,
    cur:   PassCursor&,
) -> Event, bool {
    guard io.slots[idx].state == AdapterSlotState.Open && !io.slots[idx].peer_eof_seen else {
        return Event.PassEnd, false;
    }
    let start = raw.data_off as i64;
    let end = core::add_sat_i64(start, raw.data_len);
    let slice = batch.bytes[start..end];
    if io.slots[idx].user_rx_paused {
        stash_paused_rx(io, idx, slice);
        return Event.PassEnd, false;
    }
    cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
    return Event.Data {
        link:  slot_link_handle(io, idx),
        tag:   io.slots[idx].tag,
        user:  io.slots[idx].user,
        bytes: slice,
    }, true;
}

fn step_raw_eof(io: HostLoop&, idx: i64, cur: PassCursor&) -> Event, bool {
    guard io.slots[idx].state == AdapterSlotState.Open && !io.slots[idx].peer_eof_seen else {
        return Event.PassEnd, false;
    }
    if io.slots[idx].user_rx_paused {
        io.slots[idx].paused_eof_pending = true;
        return Event.PassEnd, false;
    }
    return prepare_slot_eof_event(io, idx, cur);
}

fn step_single_raw_event(
    io:    HostLoop&,
    batch: const PollBatch&,
    raw:   const RawHostEvent&,
    cur:   PassCursor&,
) -> Event, bool {
    if raw.kind == core::LinkEventKind.Accepted {
        return step_raw_accepted(io, raw, cur);
    }
    let idx, ok = match_host_link_slot(io, raw.link);
    guard ok else { return Event.PassEnd, false; }
    match raw.kind {
        Connected => {
            guard io.slots[idx].state == AdapterSlotState.Connecting else { return Event.PassEnd, false; }
            io.slots[idx].pending_opened = false;
            io.slots[idx].has_connect_tmo = false;
            io.slots[idx].state = AdapterSlotState.Open;
            cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
            return Event.Opened {
                link:     slot_link_handle(io, idx),
                tag:      io.slots[idx].tag,
                user:     io.slots[idx].user,
                listener: io.slots[idx].listener,
            }, true;
        },
        Writable => {
            return step_raw_writable(io, idx, cur);
        },
        Data => {
            return step_raw_data(io, batch, idx, raw, cur);
        },
        Eof => {
            return step_raw_eof(io, idx, cur);
        },
        Closed => {
            record_raw_host_close(io, idx);
            return Event.PassEnd, false;
        },
        _ => {
            return Event.PassEnd, false;
        },
    };
}

fn next_raw_batch_event(io: HostLoop&, batch: const PollBatch&, cur: PassCursor&) -> Event, bool {
    while cur.raw_cursor < batch.events.len {
        let k = cur.raw_cursor;
        cur.raw_cursor = core::add_sat_i64(k, 1);
        let ev, ok = step_single_raw_event(io, batch, batch.events[k], cur);
        if ok {
            return ev, true;
        }
    }
    cur.phase = PassPhase.ReadyCloses;
    cur.slot_cursor = 0;
    return Event.PassEnd, false;
}

fn next_ready_close_event(io: HostLoop&, cur: PassCursor&) -> Event, bool {
    while cur.slot_cursor < io.slots.len {
        let i = cur.slot_cursor;
        cur.slot_cursor = core::add_sat_i64(i, 1);
        guard io.slots[i].in_use &&
            io.slots[i].state == AdapterSlotState.Closing &&
            io.slots[i].ready_to_close &&
            io.slots[i].ready_pass <= io.pass_seq else {
            continue;
        }
        io.slots[i].ready_to_close = false;
        io.slots[i].delivering_closed = true;
        cur.post_hook = PostEventHook.AfterClosed;
        cur.hook_slot = i;
        cur.hook_gen = io.slots[i].gen;
        cur.link_delivered = core::add_sat_i64(cur.link_delivered, 1);
        return Event.Closed {
            link: slot_link_handle(io, i),
            tag:  io.slots[i].tag,
            user: io.slots[i].user,
            why:  io.slots[i].close_why,
        }, true;
    }
    cur.phase = PassPhase.PassEndPhase;
    return Event.PassEnd, false;
}

fn step_due_tick_event(io: HostLoop&) -> Event, bool {
    guard !(io.run_state == LoopRunState.Draining && io.active_slot_count == 0) else {
        return Event.PassEnd, false;
    }
    let cur_ms = now_ms(io);
    let user_due = io.has_user_tick && cur_ms >= io.user_tick_ms;
    let periodic_due = cur_ms >= io.next_periodic_tick_ms;
    guard user_due || periodic_due else { return Event.PassEnd, false; }
    if user_due {
        io.has_user_tick = false;
    }
    io.next_periodic_tick_ms = core::add_sat_i64(cur_ms, HOST_LOOP_TICK_PERIOD_MS);
    return Event.Tick { now_ms: cur_ms }, true;
}

fn step_pass_phase_once(io: HostLoop&, batch: PollBatch&, cur: PassCursor&) -> Event, bool {
    match cur.phase {
        DeferredSlots => {
            return next_deferred_slot_event(io, batch, cur);
        },
        RawEvents => {
            return next_raw_batch_event(io, batch, cur);
        },
        ReadyCloses => {
            return next_ready_close_event(io, cur);
        },
        PassEndPhase => {
            cur.phase = PassPhase.TickPhase;
            return Event.PassEnd, cur.link_delivered > 0;
        },
        TickPhase => {
            cur.phase = PassPhase.Done;
            return step_due_tick_event(io);
        },
        Done => {
            return Event.PassEnd, false;
        },
    };
}

fn next_pass_event(io: HostLoop&, batch: PollBatch&, cur: PassCursor&) -> Event, bool {
    cur.post_hook = PostEventHook.None;
    while cur.phase != PassPhase.Done {
        let ev, ok = step_pass_phase_once(io, batch, cur);
        if ok {
            return ev, true;
        }
    }
    return Event.PassEnd, false;
}

fn after_pass_event(io: HostLoop&, cur: PassCursor&) {
    let hook = cur.post_hook;
    cur.post_hook = PostEventHook.None;
    if hook == PostEventHook.AfterClosed {
        finalize_closed_slot(io, cur.hook_slot);
        return;
    }
    if hook == PostEventHook.AfterPeerEof {
        let idx = cur.hook_slot;
        guard idx >= 0 && idx < io.slots.len else { return; }
        guard io.slots[idx].in_use && io.slots[idx].gen == cur.hook_gen else { return; }
        if io.slots[idx].state == AdapterSlotState.Open &&
           (!io.slots[idx].keep_open_on_eof || io.slots[idx].write_shut_sent) {
            begin_graceful_slot_close(io, idx, CloseReason.PeerClosed, io.pass_seq);
        }
    }
}

fn begin_pass(io: HostLoop&, batch: PollBatch&, cur: PassCursor&) {
    let pre_ms = now_ms(io);
    let next_pass = core::add_sat_u64(io.pass_seq, 1);
    let timeout_ms = compute_pass_timeout_ms(io, pre_ms, next_pass);
    batch.events.clear();
    batch.bytes.clear();
    let _ = net::link_poll_dispatch(io.host, batch, timeout_ms, io.last_now_ns);
    io.pass_seq = next_pass;
    let cur_ms = now_ms(io);
    sweep_pass_deadlines(io, cur_ms);
    cur = PassCursor { phase: PassPhase.DeferredSlots, .. };
}

fn serve<F>(io: HostLoop&) {
    if io.run_state == LoopRunState.Idle {
        io.run_state = LoopRunState.Running;
    }
    defer reset_loop_session(io);
    let start_ms = now_ms(io);
    io.next_periodic_tick_ms = core::add_sat_i64(start_ms, HOST_LOOP_TICK_PERIOD_MS);
    var batch = PollBatch { .. };
    var cur = PassCursor { .. };
    while !(io.run_state == LoopRunState.Draining && io.active_slot_count == 0) {
        begin_pass(io, batch, cur);
        while true {
            let ev, has_ev = next_pass_event(io, batch, cur);
            if !has_ev {
                break;
            }
            F(io, ev);
            after_pass_event(io, cur);
        }
    }
}
