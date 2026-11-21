// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal event queue, deterministic fault sampling, trace digesting, and link delivery helpers for `net::DstWorld`.
namespace net_internal;

import std;
import core;
import .transport;
import .io_host;
import .dst;

const DST_MAX_ENDPOINTS:   i64 = 64;
const DST_MAX_TCP_LINKS:   i64 = 32;
const DST_MAX_UDP_LINKS:   i64 = 32;
const DST_MAX_EVENTS:      i64 = 65536;
const DST_MAX_UDP_INBOX:   i64 = 4096;
const DST_MAX_UDP_PAYLOAD: i64 = 1500;
const DST_MAX_TCP_WINDOW:  i64 = 4096;
const DST_PPM_SCALE:       u32 = 1000000;
const DST_MIN_EPHEMERAL:   u16 = 1024;
const DST_EPHEMERAL_SPAN:  u32 = 64511;

const DST_DIGEST_SCHED_TCP:   u64 = 0x5443505343484544;
const DST_DIGEST_DELIV_TCP:   u64 = 0x54435044454C4956;
const DST_DIGEST_FIN_TCP:     u64 = 0x54435046494E0001;
const DST_DIGEST_RST_TCP:     u64 = 0x5443505253540002;
const DST_DIGEST_STALL_TCP:   u64 = 0x5443505354414C4C;
const DST_DIGEST_UDP_SCHED:   u64 = 0x5544505343484544;
const DST_DIGEST_UDP_DELIV:   u64 = 0x55445044454C4956;
const DST_DIGEST_UDP_DROP:    u64 = 0x55445044524F5003;
const DST_DIGEST_UDP_CORRUPT: u64 = 0x554450434F525204;
const DST_DIGEST_UDP_REBIND:  u64 = 0x554450524542494E;
const DST_DIGEST_TIMER:       u64 = 0x54494D4552464952;
const DST_DIGEST_CLOCK_JUMP:  u64 = 0x434C4F434B4A4D50;

struct DstEvent {
    deliver_ns:  u64               = 0,
    seq:         u64               = 0,
    timer_id:    u64               = 0,
    tag:         u64               = 0,
    payload_off: i64               = 0,
    payload_len: i32               = 0,
    src_ip4:     u32               = 0,
    src_port:    u16               = 0,
    link_id:     u16               = 0,
    owner:       u16               = 0,
    kind:        net::DstEventKind = net::DstEventKind.None,
    dir:         net::DstDir       = net::DstDir.AToB,
}

struct DstUdpInboxItem {
    link_id:  u16         = 0,
    dir:      net::DstDir = net::DstDir.AToB,
    src_ip4:  u32         = 0,
    src_port: u16         = 0,
    payload:  u8[..1500]  = [],
}

inline fn dst_dir_code(dir: net::DstDir) -> u64 {
    return if dir == net::DstDir.BToA { 1 } else { 0 };
}

fn dst_mix_event(
    world:    net::DstWorld&,
    tag_kind: u64,
    link_id:  u16,
    dir:      net::DstDir,
    ts_ns:    u64,
    payload:  const u8[:],
) {
    var h = core::hash_combine_u64(world.trace_digest, tag_kind);
    h = core::hash_combine_u64(h, link_id);
    h = core::hash_combine_u64(h, dst_dir_code(dir));
    h = core::hash_combine_u64(h, ts_ns);
    h = core::hash_combine_u64(h, payload.len as u64);
    if payload.len > 0 {
        h = core::hash_combine_u64(h, core::wyhash64(payload, h));
    }
    world.trace_digest = h;
}

inline fn dst_roll_ppm(rng: core::WyRand&, prob_ppm: u32) -> bool {
    if prob_ppm == 0 { return false; }
    if prob_ppm >= DST_PPM_SCALE { return true; }
    return core::fast_range_unbiased_u32(rng, DST_PPM_SCALE) < prob_ppm;
}

inline fn dst_sample_latency_ns(rng: core::WyRand&, min_ns: u64, max_ns: u64) -> u64 {
    guard max_ns > min_ns else { return min_ns; }
    let span = core::sub_sat_u64(max_ns, min_ns);
    let span_inc = core::add_sat_u64(span, 1);
    let jitter = core::fast_range_biased_u64(core::next_u64(rng), span_inc);
    return core::add_sat_u64(min_ns, jitter);
}

inline fn dst_sample_frag_len(rng: core::WyRand&, cfg: const net::DstFaultConfig&, remaining: i64) -> i64 {
    guard remaining > 0 else { return 0; }
    let lo = max(1, cfg.tcp_frag_min_bytes);
    let hi = if cfg.tcp_frag_max_bytes >= lo { cfg.tcp_frag_max_bytes } else { remaining };
    let capped_hi = min(hi, remaining);
    let capped_lo = min(lo, capped_hi);
    guard capped_hi > capped_lo else { return capped_lo; }
    let span = core::add_sat_i64(core::sub_sat_i64(capped_hi, capped_lo), 1) as u64;
    let delta = core::fast_range_biased_u64(core::next_u64(rng), span) as i64;
    return core::add_sat_i64(capped_lo, delta);
}

inline fn dst_sync_clock(world: net::DstWorld&, target_ns: u64) {
    if target_ns > world.now_ns {
        let skipped = core::sub_sat_u64(target_ns, world.now_ns);
        world.stats.virtual_time_skipped_ns = core::add_sat_u64(world.stats.virtual_time_skipped_ns, skipped);
        world.now_ns = target_ns;
    }
    let clamped = min(world.now_ns, 0x7FFFFFFFFFFFFFFF) as i64;
    core::sim_clock_set(clamped);
}

inline fn dst_append_payload(world: net::DstWorld&, data: const u8[:]) -> i64, i32 {
    let off = world.payload_arena.len;
    if data.len > 0 {
        world.payload_arena.append(data);
    }
    return off, (data.len & 0x7FFFFFFF) as i32;
}

inline fn dst_push_event(world: net::DstWorld&, ev: const DstEvent&) -> bool {
    guard world.events.len < DST_MAX_EVENTS else { return false; }
    var item = ev;
    item.seq = world.next_seq;
    world.next_seq = core::add_sat_u64(world.next_seq, 1);
    world.events.push(item);
    world.stats.events_scheduled = core::add_sat_u64(world.stats.events_scheduled, 1);
    return true;
}

inline fn dst_find_earliest_event_idx(world: const net::DstWorld&) -> i64 {
    guard world.events.len > 0 else { return -1; }
    var best_idx: i64 = 0;
    var best_ns:  u64 = world.events[0].deliver_ns;
    var best_seq: u64 = world.events[0].seq;
    for i in world.events.len {
        let ev .= world.events[i];
        if ev.deliver_ns < best_ns || (ev.deliver_ns == best_ns && ev.seq < best_seq) {
            best_idx = i;
            best_ns = ev.deliver_ns;
            best_seq = ev.seq;
        }
    }
    return best_idx;
}

fn dst_pop_earliest_event(world: net::DstWorld&) -> DstEvent, bool {
    let idx = dst_find_earliest_event_idx(world);
    guard idx >= 0 && idx < world.events.len else { return DstEvent { .. }, false; }
    let ev = world.events[idx];
    let last = core::sub_sat_i64(world.events.len, 1);
    if idx != last && last >= 0 && last < world.events.len {
        world.events[idx] = world.events[last];
    }
    world.events.resize(last);
    return ev, true;
}

inline fn dst_maybe_reclaim_arena(world: net::DstWorld&) {
    if world.events.len == 0 {
        world.payload_arena.clear();
    }
}

inline fn dst_tcp_dir_avail_window(link: const net::DstTcpLink&, dir: net::DstDir) -> i64, bool {
    if dir == net::DstDir.BToA {
        guard !link.rx_paused_b_to_a else { return 0, false; }
        let used = core::add_sat_i64(link.rx_b_to_a.count, link.inflight_b_to_a);
        return max(0, core::sub_sat_i64(link.rx_window_b_to_a, used)), true;
    }
    guard !link.rx_paused_a_to_b else { return 0, false; }
    let used = core::add_sat_i64(link.rx_a_to_b.count, link.inflight_a_to_b);
    return max(0, core::sub_sat_i64(link.rx_window_a_to_b, used)), true;
}

inline fn dst_tcp_next_fifo_ns(
    world:   net::DstWorld&,
    link_id: u16,
    dir:     net::DstDir,
) -> u64 {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len else { return world.now_ns; }
    let delay = dst_sample_latency_ns(
        world.rng,
        world.tcp_links[idx].faults.min_latency_ns,
        world.tcp_links[idx].faults.max_latency_ns,
    );
    let raw_ns = core::add_sat_u64(world.now_ns, delay);
    if dir == net::DstDir.BToA {
        let prev = world.tcp_links[idx].last_sched_ns_b_to_a;
        let eff = max(raw_ns, prev);
        world.tcp_links[idx].last_sched_ns_b_to_a = eff;
        return eff;
    }
    let prev = world.tcp_links[idx].last_sched_ns_a_to_b;
    let eff = max(raw_ns, prev);
    world.tcp_links[idx].last_sched_ns_a_to_b = eff;
    return eff;
}

fn dst_tcp_schedule_rst(
    world:      net::DstWorld&,
    link_id:    u16,
    dir:        net::DstDir,
    deliver_ns: u64,
) -> bool {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return false; }
    if dir == net::DstDir.BToA {
        guard !world.tcp_links[idx].rst_sent_b_to_a else { return false; }
        world.tcp_links[idx].rst_sent_b_to_a = true;
    } else {
        guard !world.tcp_links[idx].rst_sent_a_to_b else { return false; }
        world.tcp_links[idx].rst_sent_a_to_b = true;
    }
    let ev = DstEvent {
        deliver_ns: deliver_ns,
        link_id:    link_id,
        kind:       net::DstEventKind.TcpRst,
        dir:        dir,
        ..
    };
    guard dst_push_event(world, ev) else { return false; }
    dst_mix_event(world, DST_DIGEST_RST_TCP, link_id, dir, deliver_ns, "");
    return true;
}

fn dst_emit_single_tcp_chunk(
    world:   net::DstWorld&,
    link_id: u16,
    dir:     net::DstDir,
    chunk:   const u8[:],
) -> bool {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && chunk.len > 0 else { return false; }
    let deliver_ns = dst_tcp_next_fifo_ns(world, link_id, dir);
    let off, plen = dst_append_payload(world, chunk);
    let ev = DstEvent {
        deliver_ns:  deliver_ns,
        payload_off: off,
        payload_len: plen,
        link_id:     link_id,
        kind:        net::DstEventKind.TcpData,
        dir:         dir,
        ..
    };
    guard dst_push_event(world, ev) else { return false; }
    if dir == net::DstDir.BToA {
        world.tcp_links[idx].inflight_b_to_a = core::add_sat_i64(world.tcp_links[idx].inflight_b_to_a, chunk.len);
        world.tcp_links[idx].sent_bytes_b_to_a = core::add_sat_u64(
            world.tcp_links[idx].sent_bytes_b_to_a,
            chunk.len as u64,
        );
    } else {
        world.tcp_links[idx].inflight_a_to_b = core::add_sat_i64(world.tcp_links[idx].inflight_a_to_b, chunk.len);
        world.tcp_links[idx].sent_bytes_a_to_b = core::add_sat_u64(
            world.tcp_links[idx].sent_bytes_a_to_b,
            chunk.len as u64,
        );
    }
    world.stats.tcp_segments_sent = core::add_sat_u64(world.stats.tcp_segments_sent, 1);
    world.stats.tcp_bytes_sent = core::add_sat_u64(world.stats.tcp_bytes_sent, chunk.len as u64);
    dst_mix_event(world, DST_DIGEST_SCHED_TCP, link_id, dir, deliver_ns, chunk);
    return true;
}

const DST_BIT_MASKS: u8[8] = [1, 2, 4, 8, 16, 32, 64, 128];

enum DstChunkRstAction {
    Continue,
    SendThenRst,
    RstNow,
}

inline fn dst_eval_tcp_chunk_rst(
    rng:         core::WyRand&,
    cfg:         const net::DstFaultConfig&,
    sent_so_far: u64,
    take:        i64&,
) -> DstChunkRstAction {
    if cfg.tcp_rst_at_byte > 0 {
        if sent_so_far >= cfg.tcp_rst_at_byte {
            return DstChunkRstAction.RstNow;
        }
        let dist = core::sub_sat_u64(cfg.tcp_rst_at_byte, sent_so_far);
        if dist <= (take as u64) {
            take = dist as i64;
            return DstChunkRstAction.SendThenRst;
        }
    }
    if dst_roll_ppm(rng, cfg.tcp_rst_prob_ppm) {
        return DstChunkRstAction.RstNow;
    }
    return DstChunkRstAction.Continue;
}

inline fn dst_tcp_sent_bytes_for_dir(link: const net::DstTcpLink&, dir: net::DstDir) -> u64 {
    if dir == net::DstDir.BToA { return link.sent_bytes_b_to_a; }
    return link.sent_bytes_a_to_b;
}

fn dst_schedule_tcp_chunks(
    world:   net::DstWorld&,
    link_id: u16,
    dir:     net::DstDir,
    data:    const u8[:],
) -> i64 {
    let idx = link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len else { return 0; }
    var off: i64 = 0;
    while off < data.len {
        let cfg = world.tcp_links[idx].faults;
        var take = dst_sample_frag_len(world.rng, cfg, core::sub_sat_i64(data.len, off));
        guard take > 0 else { break; }
        let sent_so_far = dst_tcp_sent_bytes_for_dir(world.tcp_links[idx], dir);
        let action = dst_eval_tcp_chunk_rst(world.rng, cfg, sent_so_far, take);
        if action == DstChunkRstAction.RstNow {
            let _ = dst_tcp_schedule_rst(world, link_id, dir, dst_tcp_next_fifo_ns(world, link_id, dir));
            break;
        }
        let next_off = core::add_sat_i64(off, take);
        guard dst_emit_single_tcp_chunk(world, link_id, dir, data[off..next_off]) else { break; }
        off = next_off;
        if action == DstChunkRstAction.SendThenRst {
            let _ = dst_tcp_schedule_rst(world, link_id, dir, dst_tcp_next_fifo_ns(world, link_id, dir));
            break;
        }
    }
    return off;
}

fn dst_dispatch_tcp_data(world: net::DstWorld&, ev: const DstEvent&) -> i32 {
    let idx = ev.link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return 0; }
    let plen = ev.payload_len as i64;
    let end_off = core::add_sat_i64(ev.payload_off, plen);
    guard ev.payload_off >= 0 && plen > 0 && end_off <= world.payload_arena.len else { return 0; }

    let is_b_to_a = ev.dir == net::DstDir.BToA;
    if is_b_to_a {
        world.tcp_links[idx].inflight_b_to_a = max(0, core::sub_sat_i64(world.tcp_links[idx].inflight_b_to_a, plen));
        guard !world.tcp_links[idx].rst_recv_b_to_a else { return 0; }
    } else {
        world.tcp_links[idx].inflight_a_to_b = max(0, core::sub_sat_i64(world.tcp_links[idx].inflight_a_to_b, plen));
        guard !world.tcp_links[idx].rst_recv_a_to_b else { return 0; }
    }
    let seg = world.payload_arena[ev.payload_off..end_off];
    if world.tcp_links[idx].bridge_pipe_slot >= 0 {
        let _ = net::virtual_pipe_send(world.tcp_links[idx].bridge_pipe_slot as u16, is_b_to_a, seg);
    } else if is_b_to_a {
        let _, _ = core::write(world.tcp_links[idx].rx_b_to_a, seg);
    } else {
        let _, _ = core::write(world.tcp_links[idx].rx_a_to_b, seg);
    }
    world.stats.tcp_segments_delivered = core::add_sat_u64(world.stats.tcp_segments_delivered, 1);
    world.stats.tcp_bytes_delivered = core::add_sat_u64(world.stats.tcp_bytes_delivered, plen as u64);
    dst_mix_event(world, DST_DIGEST_DELIV_TCP, ev.link_id, ev.dir, ev.deliver_ns, seg);
    return ev.payload_len;
}

fn dst_dispatch_tcp_fin(world: net::DstWorld&, ev: const DstEvent&) {
    let idx = ev.link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return; }
    let is_b_to_a = ev.dir == net::DstDir.BToA;
    if is_b_to_a {
        world.tcp_links[idx].fin_recv_b_to_a = true;
    } else {
        world.tcp_links[idx].fin_recv_a_to_b = true;
    }
    let pidx = world.tcp_links[idx].bridge_pipe_slot;
    if pidx >= 0 && pidx < net::g_virtual_pipes.len {
        if is_b_to_a {
            net::g_virtual_pipes[pidx].closed_b = true;
        } else {
            net::g_virtual_pipes[pidx].closed_a = true;
        }
    }
    world.stats.tcp_fins_delivered = core::add_sat_u64(world.stats.tcp_fins_delivered, 1);
    dst_mix_event(world, DST_DIGEST_FIN_TCP, ev.link_id, ev.dir, ev.deliver_ns, "");
}

fn dst_dispatch_tcp_rst(world: net::DstWorld&, ev: const DstEvent&) {
    let idx = ev.link_id as i64;
    guard idx >= 0 && idx < world.tcp_links.len && world.tcp_links[idx].in_use else { return; }
    let is_b_to_a = ev.dir == net::DstDir.BToA;
    if is_b_to_a {
        world.tcp_links[idx].rst_recv_b_to_a = true;
    } else {
        world.tcp_links[idx].rst_recv_a_to_b = true;
    }
    let pidx = world.tcp_links[idx].bridge_pipe_slot;
    if pidx >= 0 {
        let _ = net::virtual_pipe_inject_rst(pidx as u16, is_b_to_a);
    }
    world.stats.tcp_rsts_injected = core::add_sat_u64(world.stats.tcp_rsts_injected, 1);
    dst_mix_event(world, DST_DIGEST_RST_TCP, ev.link_id, ev.dir, ev.deliver_ns, "");
}

fn dst_maybe_rebind_udp_port(world: net::DstWorld&, ep_id: u16, prob_ppm: u32) {
    guard dst_roll_ppm(world.rng, prob_ppm) else { return; }
    let idx = ep_id as i64;
    guard idx >= 0 && idx < world.endpoints.len && world.endpoints[idx].in_use else { return; }
    let cur = world.endpoints[idx].port;
    let delta = core::fast_range_unbiased_u32(world.rng, DST_EPHEMERAL_SPAN);
    var next_port = core::add_sat_u64(DST_MIN_EPHEMERAL, delta) as u16;
    if next_port == cur {
        next_port = if cur >= 65534 { DST_MIN_EPHEMERAL } else { core::add_sat_u64(cur, 1) as u16 };
    }
    world.endpoints[idx].port = next_port;
    world.stats.udp_nat_rebinds = core::add_sat_u64(world.stats.udp_nat_rebinds, 1);
    dst_mix_event(world, DST_DIGEST_UDP_REBIND, ep_id, net::DstDir.AToB, next_port, "");
}

fn dst_schedule_udp_copy(
    world:       net::DstWorld&,
    link_id:     u16,
    dir:         net::DstDir,
    src_ip4:     u32,
    src_port:    u16,
    deliver_ns:  u64,
    data:        const u8[:],
    corrupt_ppm: u32,
) -> bool {
    let off, plen = dst_append_payload(world, data);
    if data.len > 0 && dst_roll_ppm(world.rng, corrupt_ppm) {
        let byte_idx = core::fast_range_biased_u64(core::next_u64(world.rng), data.len as u64) as i64;
        let bit_idx = (core::next_u32(world.rng) & 7) as i64;
        let abs_idx = core::add_sat_i64(off, byte_idx);
        if abs_idx >= 0 && abs_idx < world.payload_arena.len {
            world.payload_arena[abs_idx] = world.payload_arena[abs_idx] ^ DST_BIT_MASKS[bit_idx];
            world.stats.udp_packets_corrupted = core::add_sat_u64(world.stats.udp_packets_corrupted, 1);
            dst_mix_event(world, DST_DIGEST_UDP_CORRUPT, link_id, dir, abs_idx as u64, "");
        }
    }
    let ev = DstEvent {
        deliver_ns:  deliver_ns,
        payload_off: off,
        payload_len: plen,
        src_ip4:     src_ip4,
        src_port:    src_port,
        link_id:     link_id,
        kind:        net::DstEventKind.UdpDatagram,
        dir:         dir,
        ..
    };
    guard dst_push_event(world, ev) else { return false; }
    let end_off = core::add_sat_i64(off, plen);
    if off >= 0 && end_off <= world.payload_arena.len {
        dst_mix_event(world, DST_DIGEST_UDP_SCHED, link_id, dir, deliver_ns, world.payload_arena[off..end_off]);
    }
    return true;
}

fn dst_dispatch_udp_dgram(world: net::DstWorld&, ev: const DstEvent&) -> i32 {
    let idx = ev.link_id as i64;
    guard idx >= 0 && idx < world.udp_links.len && world.udp_links[idx].in_use else { return 0; }
    guard world.udp_inbox.len < DST_MAX_UDP_INBOX else { return 0; }
    let plen = ev.payload_len as i64;
    let end_off = core::add_sat_i64(ev.payload_off, plen);
    guard ev.payload_off >= 0 && plen >= 0 && plen <= DST_MAX_UDP_PAYLOAD && end_off <= world.payload_arena.len else {
        return 0;
    }
    var item = DstUdpInboxItem {
        link_id:  ev.link_id,
        dir:      ev.dir,
        src_ip4:  ev.src_ip4,
        src_port: ev.src_port,
        ..
    };
    let dgram = world.payload_arena[ev.payload_off..end_off];
    guard item.payload.try_set(dgram) else { return 0; }
    world.udp_inbox.push(item);
    world.stats.udp_packets_delivered = core::add_sat_u64(world.stats.udp_packets_delivered, 1);
    dst_mix_event(world, DST_DIGEST_UDP_DELIV, ev.link_id, ev.dir, ev.deliver_ns, dgram);
    return ev.payload_len;
}
