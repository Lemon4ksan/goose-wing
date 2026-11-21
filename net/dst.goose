// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic Simulation Testing (DST) network, timer, clock, and fault-injection engine.
// Controlled by a single `seed: u64` across L4 TCP streams, UDP datagrams, virtual timers,
// per-endpoint clock skew/jumps, `net::Host` virtual pairs, and deterministic trace digests.
namespace net;

import std;
import core;
import .transport;
import .io_host;
import .io_host_internal;
import .dst_internal;

// Directional selector on a bidirectional virtual link.
enum DstDir {
    AToB,
    BToA,
}

// Preset deterministic network fault-injection profiles.
enum DstFaultProfile {
    Clean,
    ByteFragmented,
    LossyQuic,
    MidStreamRst,
    AdversarialChaos,
}

// Discrete event kinds processed by `DstWorld`.
enum DstEventKind {
    None,
    TcpData,
    TcpFin,
    TcpRst,
    UdpDatagram,
    Timer,
}

// Fault-injection parameters for TCP stream links and UDP datagram links.
struct DstFaultConfig {
    min_latency_ns:          u64 = 1000000,
    max_latency_ns:          u64 = 5000000,
    tcp_frag_min_bytes:      i64 = 1,
    tcp_frag_max_bytes:      i64 = 0,
    tcp_rst_prob_ppm:        u32 = 0,
    tcp_rst_at_byte:         u64 = 0,
    tcp_rx_window_bytes:     i64 = 4096,
    udp_drop_prob_ppm:       u32 = 0,
    udp_reorder_prob_ppm:    u32 = 0,
    udp_reorder_spread_ns:   u64 = 15000000,
    udp_dup_prob_ppm:        u32 = 0,
    udp_corrupt_prob_ppm:    u32 = 0,
    udp_nat_rebind_prob_ppm: u32 = 0,
}

// Virtual network endpoint with independent IPv4 address, port, and clock skew.
struct DstEndpoint {
    ip4:           u32  = 0x7F000001,
    port:          u16  = 0,
    clock_skew_ns: i64  = 0,
    in_use:        bool = false,
}

// Bidirectional fault-injecting virtual TCP link inside `DstWorld`.
struct DstTcpLink {
    ep_a:                 u16              = 0,
    ep_b:                 u16              = 0,
    faults:               DstFaultConfig   = DstFaultConfig { .. },
    rx_a_to_b:            core::RingBuffer = core::RingBuffer { .. },
    rx_b_to_a:            core::RingBuffer = core::RingBuffer { .. },
    inflight_a_to_b:      i64              = 0,
    inflight_b_to_a:      i64              = 0,
    sent_bytes_a_to_b:    u64              = 0,
    sent_bytes_b_to_a:    u64              = 0,
    last_sched_ns_a_to_b: u64              = 0,
    last_sched_ns_b_to_a: u64              = 0,
    rx_window_a_to_b:     i64              = 4096,
    rx_window_b_to_a:     i64              = 4096,
    rx_paused_a_to_b:     bool             = false,
    rx_paused_b_to_a:     bool             = false,
    fin_sent_a_to_b:      bool             = false,
    fin_sent_b_to_a:      bool             = false,
    fin_recv_a_to_b:      bool             = false,
    fin_recv_b_to_a:      bool             = false,
    rst_sent_a_to_b:      bool             = false,
    rst_sent_b_to_a:      bool             = false,
    rst_recv_a_to_b:      bool             = false,
    rst_recv_b_to_a:      bool             = false,
    bridge_pipe_slot:     i32              = -1,
    in_use:               bool             = false,
}

// Bidirectional fault-injecting virtual UDP channel for QUIC and HTTP/3.
struct DstUdpLink {
    ep_a:   u16            = 0,
    ep_b:   u16            = 0,
    faults: DstFaultConfig = DstFaultConfig { .. },
    in_use: bool           = false,
}

// Cumulative counters collected across a simulation run.
struct DstStats {
    events_scheduled:        u64 = 0,
    events_dispatched:       u64 = 0,
    tcp_segments_sent:       u64 = 0,
    tcp_segments_delivered:  u64 = 0,
    tcp_bytes_sent:          u64 = 0,
    tcp_bytes_delivered:     u64 = 0,
    tcp_rsts_injected:       u64 = 0,
    tcp_fins_delivered:      u64 = 0,
    tcp_backpressure_stalls: u64 = 0,
    udp_packets_sent:        u64 = 0,
    udp_packets_delivered:   u64 = 0,
    udp_packets_dropped:     u64 = 0,
    udp_packets_reordered:   u64 = 0,
    udp_packets_duplicated:  u64 = 0,
    udp_packets_corrupted:   u64 = 0,
    udp_nat_rebinds:         u64 = 0,
    timers_fired:            u64 = 0,
    clock_jumps:             u64 = 0,
    virtual_time_skipped_ns: u64 = 0,
}

// Outcome returned by `dst_step`.
struct DstStepResult {
    fired:    bool         = false,
    kind:     DstEventKind = DstEventKind.None,
    now_ns:   u64          = 0,
    link_id:  u16          = 0,
    dir:      DstDir       = DstDir.AToB,
    timer_id: u64          = 0,
    owner:    u16          = 0,
    tag:      u64          = 0,
    bytes:    i32          = 0,
}

// Root owner holding deterministic simulation state, event queue, links, and trace digest.
root struct DstWorld {
    seed:          u64                                 = 0,
    now_ns:        u64                                 = 0,
    next_seq:      u64                                 = 1,
    trace_digest:  u64                                 = core::FNV1A_64_OFFSET,
    rng:           core::WyRand                        = core::WyRand { .. },
    stats:         DstStats                            = DstStats { .. },
    endpoints:     DstEndpoint[>..]                    = [],
    tcp_links:     DstTcpLink[>..]                     = [],
    udp_links:     DstUdpLink[>..]                     = [],
    udp_inbox:     net_internal::DstUdpInboxItem[>..<] = [],
    events:        net_internal::DstEvent[>..<]        = [],
    payload_arena: u8[>..]                             = [],
    active:        bool                                = false,
}

// Returns a pre-configured `DstFaultConfig` for common simulation fault profiles.
fn dst_fault_profile(profile: DstFaultProfile) -> DstFaultConfig {
    return match profile {
        Clean => DstFaultConfig {
            min_latency_ns: 1000000,
            max_latency_ns: 2000000,
            ..
        },
        ByteFragmented => DstFaultConfig {
            min_latency_ns:     500000,
            max_latency_ns:     3000000,
            tcp_frag_min_bytes: 1,
            tcp_frag_max_bytes: 1,
            ..
        },
        LossyQuic => DstFaultConfig {
            min_latency_ns:          2000000,
            max_latency_ns:          12000000,
            udp_drop_prob_ppm:       150000,
            udp_reorder_prob_ppm:    250000,
            udp_reorder_spread_ns:   20000000,
            udp_dup_prob_ppm:        100000,
            udp_corrupt_prob_ppm:    50000,
            udp_nat_rebind_prob_ppm: 100000,
            ..
        },
        MidStreamRst => DstFaultConfig {
            min_latency_ns:     500000,
            max_latency_ns:     2000000,
            tcp_frag_min_bytes: 1,
            tcp_frag_max_bytes: 7,
            tcp_rst_at_byte:    32,
            ..
        },
        AdversarialChaos => DstFaultConfig {
            min_latency_ns:          1000000,
            max_latency_ns:          25000000,
            tcp_frag_min_bytes:      1,
            tcp_frag_max_bytes:      13,
            tcp_rst_prob_ppm:        25000,
            tcp_rx_window_bytes:     512,
            udp_drop_prob_ppm:       200000,
            udp_reorder_prob_ppm:    350000,
            udp_reorder_spread_ns:   30000000,
            udp_dup_prob_ppm:        150000,
            udp_corrupt_prob_ppm:    80000,
            udp_nat_rebind_prob_ppm: 150000,
            ..
        },
    };
}

// Initializes `world` from `seed` and enables deterministic virtual clock and simulation CSPRNG.
fn dst_init(world: DstWorld&, seed: u64, start_ns: u64 = 1000000000) {
    world.seed = seed;
    world.now_ns = start_ns;
    world.next_seq = 1;
    world.trace_digest = core::FNV1A_64_OFFSET ^ seed;
    world.rng = core::new_wyrand(seed);
    world.stats = DstStats { .. };
    world.endpoints.clear();
    world.tcp_links.clear();
    world.udp_links.clear();
    world.udp_inbox.clear();
    world.events.clear();
    world.payload_arena.clear();
    world.active = true;
    let clamped = min(start_ns, 0x7FFFFFFFFFFFFFFF) as i64;
    core::sim_clock_enable(clamped);
    core::sim_rng_enable(seed);
}

// Disables deterministic simulation clock/entropy hooks and clears `world` buffers.
fn dst_shutdown(world: DstWorld&) {
    core::sim_clock_disable();
    core::sim_rng_disable();
    world.endpoints.clear();
    world.tcp_links.clear();
    world.udp_links.clear();
    world.udp_inbox.clear();
    world.events.clear();
    world.payload_arena.clear();
    world.active = false;
}

// Registers a simulated endpoint with IPv4 address, port, and optional signed clock skew.
fn dst_add_endpoint(
    world:         DstWorld&,
    ip4:           u32,
    port:          u16,
    clock_skew_ns: i64 = 0,
) -> u16, bool {
    guard world.active && world.endpoints.len < net_internal::DST_MAX_ENDPOINTS else {
        return 0, false;
    }
    let idx = world.endpoints.len;
    world.endpoints.push(DstEndpoint {
        ip4:           ip4,
        port:          port,
        clock_skew_ns: clock_skew_ns,
        in_use:        true,
    });
    return (idx & 0xFFFF) as u16, true;
}

// Updates the per-endpoint signed clock skew in nanoseconds.
fn dst_set_endpoint_skew(world: DstWorld&, ep_id: u16, skew_ns: i64) -> bool {
    let idx = ep_id as i64;
    guard idx >= 0 && idx < world.endpoints.len && world.endpoints[idx].in_use else { return false; }
    world.endpoints[idx].clock_skew_ns = skew_ns;
    return true;
}

// Computes the endpoint's local virtual clock in nanoseconds (global clock plus endpoint skew).
fn dst_endpoint_now_ns(world: const DstWorld&, ep_id: u16) -> u64 {
    let idx = ep_id as i64;
    guard idx >= 0 && idx < world.endpoints.len && world.endpoints[idx].in_use else {
        return world.now_ns;
    }
    let skew = world.endpoints[idx].clock_skew_ns;
    if skew >= 0 {
        return core::add_sat_u64(world.now_ns, skew as u64);
    }
    let neg_mag = core::sub_sat_i64(0, skew) as u64;
    return core::sub_sat_u64(world.now_ns, neg_mag);
}

// Computes the endpoint's local virtual clock in whole seconds.
fn dst_endpoint_now_sec(world: const DstWorld&, ep_id: u16) -> i64 {
    let ns = min(dst_endpoint_now_ns(world, ep_id), 0x7FFFFFFFFFFFFFFF) as i64;
    return core::unix_nano(ns).wall_sec;
}

// Instantly jumps the global virtual clock forward by `delta_ns` nanoseconds.
fn dst_jump_clock(world: DstWorld&, delta_ns: u64) {
    guard world.active && delta_ns > 0 else { return; }
    let next_ns = core::add_sat_u64(world.now_ns, delta_ns);
    net_internal::dst_sync_clock(world, next_ns);
    world.stats.clock_jumps = core::add_sat_u64(world.stats.clock_jumps, 1);
    net_internal::dst_mix_event(world, net_internal::DST_DIGEST_CLOCK_JUMP, 0, DstDir.AToB, next_ns, "");
}

// Opens a bidirectional fault-injecting virtual TCP link between `ep_a` and `ep_b`.
fn dst_open_tcp_link(
    world:  DstWorld&,
    ep_a:   u16,
    ep_b:   u16,
    faults: const DstFaultConfig&,
) -> u16, bool {
    guard world.active && world.tcp_links.len < net_internal::DST_MAX_TCP_LINKS else {
        return 0, false;
    }
    let ia = ep_a as i64;
    let ib = ep_b as i64;
    guard ia >= 0 && ia < world.endpoints.len && ib >= 0 && ib < world.endpoints.len else {
        return 0, false;
    }
    let win = if faults.tcp_rx_window_bytes > 0 {
        min(faults.tcp_rx_window_bytes, net_internal::DST_MAX_TCP_WINDOW)
    } else {
        net_internal::DST_MAX_TCP_WINDOW
    };
    let idx = world.tcp_links.len;
    world.tcp_links.push(DstTcpLink {
        ep_a:             ep_a,
        ep_b:             ep_b,
        faults:           faults,
        rx_window_a_to_b: win,
        rx_window_b_to_a: win,
        in_use:           true,
        ..
    });
    return (idx & 0xFFFF) as u16, true;
}

// Bridges a `DstTcpLink` onto a `net::Host` virtual link pair so delivered segments/FIN/RST
// surface as `core::LinkEvent` push notifications (`Data`, `Eof`, `Closed`).
fn dst_attach_host_pair(
    world:   DstWorld&,
    host:    Host&,
    link_id: u16,
    owner_a: u16,
    owner_b: u16,
) -> core::IoLink, core::IoLink, bool {
    let idx = link_id as i64;
    guard world.active && idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else {
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    guard world.tcp_links[idx].bridge_pipe_slot < 0 else {
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    let la, lb, ok = open_virtual_pair(host, owner_a, owner_b, link_id, link_id);
    guard ok else { return core::IoLink { .. }, core::IoLink { .. }, false; }
    let slot_a, ok_sa = net_internal::host_match_link(host, la);
    guard ok_sa else { return core::IoLink { .. }, core::IoLink { .. }, false; }
    world.tcp_links[idx].bridge_pipe_slot = host.links[slot_a].virtual_pair;
    return la, lb, true;
}

// Replaces the active `DstFaultConfig` on an open TCP link.
fn dst_set_tcp_faults(world: DstWorld&, link_id: u16, faults: const DstFaultConfig&) -> bool {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return false; }
    world.tcp_links[idx].faults = faults;
    if faults.tcp_rx_window_bytes > 0 {
        let win = min(faults.tcp_rx_window_bytes, net_internal::DST_MAX_TCP_WINDOW);
        world.tcp_links[idx].rx_window_a_to_b = win;
        world.tcp_links[idx].rx_window_b_to_a = win;
    }
    return true;
}

// Configures the receive-window cap (bytes) for throttling/backpressure in direction `dir`.
fn dst_tcp_set_rx_window(world: DstWorld&, link_id: u16, dir: DstDir, window_bytes: i64) -> bool {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return false; }
    let clamped = min(max(0, window_bytes), net_internal::DST_MAX_TCP_WINDOW);
    if dir == DstDir.BToA {
        world.tcp_links[idx].rx_window_b_to_a = clamped;
    } else {
        world.tcp_links[idx].rx_window_a_to_b = clamped;
    }
    return true;
}

// Pauses or resumes receiver acceptance for direction `dir` (triggers `WouldBlock` backpressure).
fn dst_tcp_set_rx_paused(world: DstWorld&, link_id: u16, dir: DstDir, paused: bool) -> bool {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return false; }
    if dir == DstDir.BToA {
        world.tcp_links[idx].rx_paused_b_to_a = paused;
    } else {
        world.tcp_links[idx].rx_paused_a_to_b = paused;
    }
    return true;
}

// Enqueues TCP stream bytes for fragmented, delayed, and fault-injected delivery in `dir`.
fn dst_tcp_send(
    world:   DstWorld&,
    link_id: u16,
    dir:     DstDir,
    data:    const u8[:],
) -> i64, core::IoError {
    let idx = link_id as i64;
    guard world.active && idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else {
        return 0, core::IoError.InvalidArgument;
    }
    guard data.len > 0 else { return 0, core::IoError.None; }
    let is_closed = if dir == DstDir.BToA {
        world.tcp_links[idx].fin_sent_b_to_a || world.tcp_links[idx].rst_sent_b_to_a ||
        world.tcp_links[idx].rst_recv_a_to_b || world.tcp_links[idx].rst_recv_b_to_a
    } else {
        world.tcp_links[idx].fin_sent_a_to_b || world.tcp_links[idx].rst_sent_a_to_b ||
        world.tcp_links[idx].rst_recv_a_to_b || world.tcp_links[idx].rst_recv_b_to_a
    };
    guard !is_closed else { return 0, core::IoError.Closed; }

    let avail, unpaused = net_internal::dst_tcp_dir_avail_window(world.tcp_links[idx], dir);
    if !unpaused || avail <= 0 {
        world.stats.tcp_backpressure_stalls = core::add_sat_u64(world.stats.tcp_backpressure_stalls, 1);
        net_internal::dst_mix_event(world, net_internal::DST_DIGEST_STALL_TCP, link_id, dir, world.now_ns, "");
        return 0, core::IoError.WouldBlock;
    }
    let budget = min(data.len, avail);
    let sent = net_internal::dst_schedule_tcp_chunks(world, link_id, dir, data[..budget]);
    if sent < data.len && budget < data.len {
        world.stats.tcp_backpressure_stalls = core::add_sat_u64(world.stats.tcp_backpressure_stalls, 1);
        return sent, core::IoError.ShortWrite;
    }
    return sent, core::IoError.None;
}

// Reads delivered TCP stream bytes for direction `dir` into `dst`.
// Returns `(bytes, IoError.None)`, `(0, IoError.WouldBlock)`, `(0, IoError.Eof)`, or `(0, IoError.Closed)` on RST.
fn dst_tcp_recv(
    world:   DstWorld&,
    link_id: u16,
    dir:     DstDir,
    dst:     u8[:],
) -> i32, core::IoError {
    let idx = link_id as i64;
    guard world.active && idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else {
        return 0, core::IoError.InvalidArgument;
    }
    guard dst.len > 0 else { return 0, core::IoError.None; }
    let is_b_to_a = dir == DstDir.BToA;
    var rb .= world.tcp_links[idx].rx_a_to_b;
    if is_b_to_a {
        rb .= world.tcp_links[idx].rx_b_to_a;
    }
    if rb.count > 0 {
        let n_read, _ = core::read(rb, dst);
        return (n_read & 0x7FFFFFFF) as i32, core::IoError.None;
    }
    let got_rst = if is_b_to_a { world.tcp_links[idx].rst_recv_b_to_a } else { world.tcp_links[idx].rst_recv_a_to_b };
    if got_rst { return 0, core::IoError.Closed; }
    let got_fin = if is_b_to_a { world.tcp_links[idx].fin_recv_b_to_a } else { world.tcp_links[idx].fin_recv_a_to_b };
    if got_fin { return 0, core::IoError.Eof; }
    return 0, core::IoError.WouldBlock;
}

// Schedules a graceful TCP half-close FIN in direction `dir` after in-flight segments.
fn dst_tcp_shutdown_write(world: DstWorld&, link_id: u16, dir: DstDir) -> bool {
    let idx = link_id as i64;
    guard world.active && idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return false; }
    if dir == DstDir.BToA {
        guard !world.tcp_links[idx].fin_sent_b_to_a else { return false; }
        world.tcp_links[idx].fin_sent_b_to_a = true;
    } else {
        guard !world.tcp_links[idx].fin_sent_a_to_b else { return false; }
        world.tcp_links[idx].fin_sent_a_to_b = true;
    }
    let deliver_ns = net_internal::dst_tcp_next_fifo_ns(world, link_id, dir);
    let ev = net_internal::DstEvent {
        deliver_ns: deliver_ns,
        link_id:    link_id,
        kind:       DstEventKind.TcpFin,
        dir:        dir,
        ..
    };
    return net_internal::dst_push_event(world, ev);
}

// Schedules an explicit mid-stream TCP RST in direction `dir` after `delay_ns`.
fn dst_tcp_inject_rst(world: DstWorld&, link_id: u16, dir: DstDir, delay_ns: u64 = 0) -> bool {
    guard world.active else { return false; }
    let deliver_ns = core::add_sat_u64(world.now_ns, delay_ns);
    return net_internal::dst_tcp_schedule_rst(world, link_id, dir, deliver_ns);
}

// Opens a bidirectional fault-injecting virtual UDP channel for QUIC / HTTP/3 simulation.
fn dst_open_udp_link(
    world:  DstWorld&,
    ep_a:   u16,
    ep_b:   u16,
    faults: const DstFaultConfig&,
) -> u16, bool {
    guard world.active && world.udp_links.len < net_internal::DST_MAX_UDP_LINKS else {
        return 0, false;
    }
    let ia = ep_a as i64;
    let ib = ep_b as i64;
    guard ia >= 0 && ia < world.endpoints.len && ib >= 0 && ib < world.endpoints.len else {
        return 0, false;
    }
    let idx = world.udp_links.len;
    world.udp_links.push(DstUdpLink {
        ep_a:   ep_a,
        ep_b:   ep_b,
        faults: faults,
        in_use: true,
    });
    return (idx & 0xFFFF) as u16, true;
}

// Explicitly rebinds an endpoint's UDP port (deterministic NAT migration trigger).
fn dst_udp_rebind_endpoint_port(world: DstWorld&, ep_id: u16, new_port: u16) -> bool {
    let idx = ep_id as i64;
    guard world.active && idx >= 0 && idx < world.endpoints.len && world.endpoints[idx].in_use && new_port != 0 else {
        return false;
    }
    world.endpoints[idx].port = new_port;
    world.stats.udp_nat_rebinds = core::add_sat_u64(world.stats.udp_nat_rebinds, 1);
    net_internal::dst_mix_event(world, net_internal::DST_DIGEST_UDP_REBIND, ep_id, DstDir.AToB, new_port, "");
    return true;
}

// Sends a UDP datagram across `link_id` applying drop, reorder, duplicate, corruption, and NAT rebind faults.
fn dst_udp_send(world: DstWorld&, link_id: u16, dir: DstDir, data: const u8[:]) -> bool {
    let idx = link_id as i64;
    guard world.active && idx >= 0 && idx < world.udp_links.len && world.udp_links[idx].in_use else { return false; }
    guard data.len > 0 && data.len <= net_internal::DST_MAX_UDP_PAYLOAD else { return false; }

    let cfg = world.udp_links[idx].faults;
    let src_ep = if dir == DstDir.BToA { world.udp_links[idx].ep_b } else { world.udp_links[idx].ep_a };
    let ep_idx = src_ep as i64;
    guard ep_idx >= 0 && ep_idx < world.endpoints.len else { return false; }

    world.stats.udp_packets_sent = core::add_sat_u64(world.stats.udp_packets_sent, 1);
    net_internal::dst_maybe_rebind_udp_port(world, src_ep, cfg.udp_nat_rebind_prob_ppm);
    let src_ip4 = world.endpoints[ep_idx].ip4;
    let src_port = world.endpoints[ep_idx].port;

    if net_internal::dst_roll_ppm(world.rng, cfg.udp_drop_prob_ppm) {
        world.stats.udp_packets_dropped = core::add_sat_u64(world.stats.udp_packets_dropped, 1);
        net_internal::dst_mix_event(world, net_internal::DST_DIGEST_UDP_DROP, link_id, dir, world.now_ns, data);
        return true;
    }
    var delay = net_internal::dst_sample_latency_ns(world.rng, cfg.min_latency_ns, cfg.max_latency_ns);
    if net_internal::dst_roll_ppm(world.rng, cfg.udp_reorder_prob_ppm) && cfg.udp_reorder_spread_ns > 0 {
        let extra = core::add_sat_u64(
            1,
            core::fast_range_biased_u64(core::next_u64(world.rng), cfg.udp_reorder_spread_ns),
        );
        delay = core::add_sat_u64(delay, extra);
        world.stats.udp_packets_reordered = core::add_sat_u64(world.stats.udp_packets_reordered, 1);
    }
    let deliver_ns = core::add_sat_u64(world.now_ns, delay);
    guard net_internal::dst_schedule_udp_copy(
        world, link_id, dir, src_ip4, src_port, deliver_ns, data, cfg.udp_corrupt_prob_ppm,
    ) else { return false; }

    if net_internal::dst_roll_ppm(world.rng, cfg.udp_dup_prob_ppm) {
        let dup_extra = net_internal::dst_sample_latency_ns(world.rng, 100000, max(100000, cfg.max_latency_ns));
        let dup_ns = core::add_sat_u64(deliver_ns, dup_extra);
        if net_internal::dst_schedule_udp_copy(
            world, link_id, dir, src_ip4, src_port, dup_ns, data, cfg.udp_corrupt_prob_ppm,
        ) {
            world.stats.udp_packets_duplicated = core::add_sat_u64(world.stats.udp_packets_duplicated, 1);
        }
    }
    return true;
}

// Pops the next delivered UDP datagram for `(link_id, dir)` into `dst`, returning `(len, src_ip4, src_port, ok)`.
fn dst_udp_recv(world: DstWorld&, link_id: u16, dir: DstDir, dst: u8[:]) -> i32, u32, u16, bool {
    guard world.active && dst.len > 0 else { return 0, 0, 0, false; }
    var match_idx: i64 = -1;
    for i in world.udp_inbox.len {
        if world.udp_inbox[i].link_id == link_id && world.udp_inbox[i].dir == dir {
            match_idx = i;
            break;
        }
    }
    guard match_idx >= 0 && match_idx < world.udp_inbox.len else { return 0, 0, 0, false; }
    let src_ip4 = world.udp_inbox[match_idx].src_ip4;
    let src_port = world.udp_inbox[match_idx].src_port;
    let copy_len = min(world.udp_inbox[match_idx].payload.len, dst.len);
    for k in copy_len {
        dst[k] = world.udp_inbox[match_idx].payload[k];
    }
    let last = core::sub_sat_i64(world.udp_inbox.len, 1);
    var pos = match_idx;
    while pos < last {
        let next_pos = core::add_sat_i64(pos, 1);
        if next_pos < world.udp_inbox.len {
            world.udp_inbox[pos] = world.udp_inbox[next_pos];
        }
        pos = next_pos;
    }
    world.udp_inbox.resize(last);
    return (copy_len & 0x7FFFFFFF) as i32, src_ip4, src_port, true;
}

// Schedules a virtual timer event firing after `delay_ns` nanoseconds.
fn dst_schedule_timer(
    world:    DstWorld&,
    timer_id: u64,
    delay_ns: u64,
    owner:    u16,
    tag:      u64,
) -> bool {
    guard world.active && timer_id != 0 else { return false; }
    let ev = net_internal::DstEvent {
        deliver_ns: core::add_sat_u64(world.now_ns, delay_ns),
        timer_id:   timer_id,
        tag:        tag,
        owner:      owner,
        kind:       DstEventKind.Timer,
        ..
    };
    return net_internal::dst_push_event(world, ev);
}

// Cancels pending virtual timer events matching `timer_id`.
fn dst_cancel_timer(world: DstWorld&, timer_id: u64) -> bool {
    guard world.active && timer_id != 0 else { return false; }
    var removed = false;
    var i: i64 = 0;
    while i < world.events.len {
        if world.events[i].kind == DstEventKind.Timer && world.events[i].timer_id == timer_id {
            let last = core::sub_sat_i64(world.events.len, 1);
            if i != last && last >= 0 && last < world.events.len {
                world.events[i] = world.events[last];
            }
            world.events.resize(last);
            removed = true;
            continue;
        }
        i = core::add_sat_i64(i, 1);
    }
    net_internal::dst_maybe_reclaim_arena(world);
    return removed;
}

// Returns the timestamp of the next scheduled event in `world`, or `(0, false)` when idle.
fn dst_next_event_ns(world: const DstWorld&) -> u64, bool {
    let idx = net_internal::dst_find_earliest_event_idx(world);
    guard idx >= 0 && idx < world.events.len else { return 0, false; }
    return world.events[idx].deliver_ns, true;
}

// Advances virtual time directly to the next scheduled event and dispatches it.
fn dst_step(world: DstWorld&) -> DstStepResult {
    guard world.active else { return DstStepResult { .. }; }
    let ev, ok = net_internal::dst_pop_earliest_event(world);
    guard ok else { return DstStepResult { now_ns: world.now_ns, .. }; }

    net_internal::dst_sync_clock(world, ev.deliver_ns);
    world.stats.events_dispatched = core::add_sat_u64(world.stats.events_dispatched, 1);

    var delivered_bytes: i32 = 0;
    if ev.kind == DstEventKind.TcpData {
        delivered_bytes = net_internal::dst_dispatch_tcp_data(world, ev);
    } else if ev.kind == DstEventKind.TcpFin {
        net_internal::dst_dispatch_tcp_fin(world, ev);
    } else if ev.kind == DstEventKind.TcpRst {
        net_internal::dst_dispatch_tcp_rst(world, ev);
    } else if ev.kind == DstEventKind.UdpDatagram {
        delivered_bytes = net_internal::dst_dispatch_udp_dgram(world, ev);
    } else if ev.kind == DstEventKind.Timer {
        world.stats.timers_fired = core::add_sat_u64(world.stats.timers_fired, 1);
        net_internal::dst_mix_event(world, net_internal::DST_DIGEST_TIMER, ev.owner, DstDir.AToB, ev.timer_id, "");
    }
    net_internal::dst_maybe_reclaim_arena(world);
    return DstStepResult {
        fired:    true,
        kind:     ev.kind,
        now_ns:   world.now_ns,
        link_id:  ev.link_id,
        dir:      ev.dir,
        timer_id: ev.timer_id,
        owner:    ev.owner,
        tag:      ev.tag,
        bytes:    delivered_bytes,
    };
}

// Dispatches all scheduled events up to `max_ns`, then fast-forwards virtual time to `max_ns`.
fn dst_run_until(world: DstWorld&, max_ns: u64, max_steps: i64 = 100000) -> i64 {
    guard world.active && max_steps > 0 else { return 0; }
    var steps: i64 = 0;
    while steps < max_steps {
        let next_ns, has_ev = dst_next_event_ns(world);
        guard has_ev && next_ns <= max_ns else { break; }
        let res = dst_step(world);
        guard res.fired else { break; }
        steps = core::add_sat_i64(steps, 1);
    }
    net_internal::dst_sync_clock(world, max_ns);
    return steps;
}

// Jumps virtual time to the earliest pending `DstWorld` event or `net::Host` timer,
// dispatches due network deliveries into bridged virtual pipes, and polls `host`.
fn dst_step_host<D>(world: DstWorld&, host: Host&, driver: D&) -> i32 {
    guard world.active && host.is_open else { return 0; }
    let w_ns, has_w = dst_next_event_ns(world);
    let h_ns, has_h = host_next_timer_ns(host);
    if has_w && (!has_h || w_ns <= h_ns) {
        let _ = dst_step(world);
    } else if has_h {
        net_internal::dst_sync_clock(world, h_ns);
    }
    return link_poll_dispatch(host, driver, 0, world.now_ns);
}
