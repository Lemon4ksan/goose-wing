// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for ACK recovery, congestion control, DPLPMTUD, migration, flow control, and streams.
namespace quic_internal;

import std;
import core from "..";
import .packet;
import .AckFrame;
import .bbr;
import .dplpmtud;
import .migration;
import .flow_control;
import .stream;

// ---- ACK Frame, Loss Recovery & PTO Internal Helpers ---------------------

// Computes the next descending ACK interval `[smallest, largest]` from `prev_smallest`, `gap`, and `ack_range`
// per RFC 9000 Section 19.3.1, rejecting underflow.
inline fn step_descending_ack_range(prev_smallest: u64, gap: u64, ack_range: u64) -> quic::AckInterval, bool {
    guard prev_smallest >= 2 && core::sub_sat_u64(prev_smallest, 2) >= gap else {
        return quic::AckInterval {}, false;
    }
    let cur_largest = core::sub_sat_u64(core::sub_sat_u64(prev_smallest, 2), gap);
    guard cur_largest >= ack_range else { return quic::AckInterval {}, false; }
    let cur_smallest = core::sub_sat_u64(cur_largest, ack_range);
    return quic::AckInterval { smallest: cur_smallest, largest: cur_largest }, true;
}

// Decodes sequential ACK gap and range fields.
// Restores `cur` and `ack.ranges` on failure (`false`).
//
// Example:
//   src = [0x00, 0x01], cur = 0, range_cnt = 1
//   returns: ok = true, cur = 2
fn decode_ack_frame_ranges(
    src:           const u8[:],
    cur:           u64&,
    range_cnt:     u64,
    largest_acked: u64,
    first_range:   u64,
    ack:           quic::AckFrame&,
) -> bool {
    let saved_cur = cur;
    let saved_len = ack.ranges.len;
    var committed = false;
    defer if !committed {
        cur = saved_cur;
        ack.ranges.resize(saved_len);
    };
    var cur_smallest = core::sub_sat_u64(largest_acked, first_range);
    var r_idx: u64 = 0;
    while r_idx < range_cnt {
        let gap, next_cur_g, okg = quic::decode_varint(src, cur);
        guard okg else { return false; }
        cur = next_cur_g;
        let rlen, next_cur_r, okr = quic::decode_varint(src, cur);
        guard okr else { return false; }
        cur = next_cur_r;

        let iv, ok_iv = step_descending_ack_range(cur_smallest, gap, rlen);
        guard ok_iv else { return false; }
        cur_smallest = iv.smallest;

        if ack.ranges.len < ack.ranges.cap {
            let _ = ack.ranges.try_push(quic::AckRange { gap: gap, ack_range: rlen });
        } else {
            // Saturated capacity; RFC 9000 §19.3.1 permits ignoring older ranges.
        }
        r_idx = core::add_sat_u64(r_idx, 1);
    }
    committed = true;
    return true;
}

inline fn rtt_abs_diff(a: u64, b: u64) -> u64 {
    return core::sub_sat_u64(max(a, b), min(a, b));
}

inline fn calc_space_loss_delay(rtt: const quic::RttState&) -> u64 {
    let max_rtt = max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
    let scaled = core::mul_sat_u64(max_rtt, rfc::QUIC_LOSS_TIME_NUMERATOR) >> 3;
    return max(scaled, rfc::QUIC_TIMER_GRANULARITY_US);
}

inline fn is_sent_packet_lost(
    pkt:              const quic::SentPacketMeta&,
    largest_acked_pn: u64,
    lost_send_time:   u64,
) -> bool {
    guard pkt.pn <= largest_acked_pn else { return false; }
    let pkt_thresh = core::add_sat_u64(pkt.pn, rfc::QUIC_LOSS_PACKET_THRESHOLD);
    return largest_acked_pn >= pkt_thresh || pkt.time_sent_us <= lost_send_time;
}

inline fn update_space_next_loss_time(
    space:      quic::PnSpaceState&,
    pkt:        const quic::SentPacketMeta&,
    loss_delay: u64,
) {
    guard pkt.pn <= space.largest_acked_pn else { return; }
    let next_loss_time = core::add_sat_u64(pkt.time_sent_us, loss_delay);
    if space.loss_time_us == 0 || next_loss_time < space.loss_time_us {
        space.loss_time_us = next_loss_time;
    }
}

inline fn compact_remaining_sent_packets(space: quic::PnSpaceState&, start_idx: i64, write_idx: u64) {
    var w = write_idx;
    for rem_i in start_idx..space.sent_packets.len {
        space.sent_packets[w as i64] = space.sent_packets[rem_i];
        w = core::add_sat_u64(w, 1);
    }
    space.sent_packets.resize(w as i64, quic::SentPacketMeta { .. });
}

// Finds earliest loss detection time across all active spaces (Priority 1).
fn get_earliest_loss_time(spaces: const quic::PnSpaceState[3]&) -> u64, quic::PnSpaceId {
    var earliest: u64 = 0;
    var space_id = quic::PnSpaceId.Initial;

    for i in 3 {
        let lt = spaces[i].loss_time_us;
        if lt != 0 && (earliest == 0 || lt < earliest) {
            earliest = lt;
            space_id = spaces[i].space_id;
        }
    }
    return earliest, space_id;
}

fn count_in_flight_eliciting(spaces: const quic::PnSpaceState[3]&, handshake_confirmed: bool = true) -> u64 {
    var count: u64 = 0;
    for s in 3 {
        if spaces[s].space_id == quic::PnSpaceId.ApplicationData && !handshake_confirmed {
            continue;
        }
        for p in spaces[s].sent_packets.len {
            if spaces[s].sent_packets[p].ack_eliciting {
                count = core::add_sat_u64(count, 1);
            }
        }
    }
    return count;
}

fn find_earliest_standard_pto(
    spaces:              const quic::PnSpaceState[3]&,
    rtt:                 const quic::RttState&,
    pto_count:           u32,
    handshake_confirmed: bool,
) -> u64, quic::PnSpaceId {
    var earliest_pto: u64 = 0;
    var target_sp = quic::PnSpaceId.Initial;
    for s in 3 {
        let space .= spaces[s];
        var space_has_eliciting = false;
        for p in space.sent_packets.len {
            if space.sent_packets[p].ack_eliciting { space_has_eliciting = true; break; }
        }
        if !space_has_eliciting { continue; }
        if space.space_id == quic::PnSpaceId.ApplicationData && !handshake_confirmed {
            continue;
        }

        let is_app = space.space_id == quic::PnSpaceId.ApplicationData;
        let dur = quic::compute_pto_duration(rtt, pto_count, is_app);
        let t = core::add_sat_u64(space.time_of_last_ack_eliciting_us, dur);
        if earliest_pto == 0 || t < earliest_pto {
            earliest_pto = t;
            target_sp = space.space_id;
        }
    }
    return earliest_pto, target_sp;
}

// ---- Congestion Control Internal Helpers ---------------------------------

const BBR_BETA_NUM:   u64 = 70; // 0.7 inflight reduction on congestion
const BBR_BETA_DENOM: u64 = 100;

// Computes floor(cbrt(val)) using integer binary search up to 2,642,245.
fn int_cbrt(val: u64) -> u64 {
    guard val > 0 else { return 0; }
    var low:  u64 = 1;
    var high: u64 = 2642245; // 2_642_245^3 = 18_446_742_000_000_000_000 <= u64::MAX
    var ans:  u64 = 1;

    while low <= high {
        let mid = (low + high) / 2;
        let sq = mid * mid;
        if sq <= (0xFFFFFFFFFFFFFFFF / mid) && (sq * mid) <= val {
            ans = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    return ans;
}

// Sets current pacing rate, enforcing a 64 kbps safety floor.
fn pacer_set_rate(pacer: quic::Pacer&, rate_bps: u64) {
    pacer.pacing_rate_bps = max(rate_bps, 64000);
}

// Computes K = cbrt(w_max * beta / C) in milliseconds (RFC 9438 Section 4.1).
fn cubic_compute_k(w_max: u64) -> u64 {
    // K = cbrt((w_max * (1 - 0.7)) / 0.4) = cbrt((w_max * 3) / 4)
    // Multiplied by 10^9 before cbrt to obtain millisecond precision
    let w_diff = core::mul_sat_u64(w_max, 3) / 4;
    return int_cbrt(core::mul_sat_u64(w_diff, 1000000000));
}

// ---- DPLPMTUD Internal Helpers -------------------------------------------

const CANDIDATE_PMTU_COUNT: u32 = 4;

// RFC 8899 Section 5.1.2: The Searching State - Table of candidate PMTU probe sizes
inline fn get_candidate_pmtu(idx: u32) -> u32 {
    if idx == 0 { return rfc::PMTU_BASE; }
    if idx == 1 { return rfc::PMTU_IPV6_MIN; }
    if idx == 2 { return rfc::PMTU_INTERMEDIATE; }
    return rfc::PMTU_ETHERNET;
}

// ---- Migration Anti-Amplification Internal Helper ------------------------

// RFC 9000 Section 8.1: Address Validation during Connection Initiation - 3x anti-amplification budget
inline fn path_amplification_limit(rx: u64) -> u64 {
    if rx > (0xFFFFFFFFFFFFFFFF / 3) {
        return 0xFFFFFFFFFFFFFFFF;
    }
    return rx * 3;
}

// ---- Flow Control Internal Helpers ---------------------------------------

// Computes unspent flow control allowance safely guarding against underflow (RFC 9000 §4.1).
inline fn calc_unspent_credit(limit: u64, consumed: u64) -> u64 {
    guard limit > consumed else { return 0; }
    return limit - consumed;
}

// Calculates candidate window credit advertisement clamped to 2^62 - 1 (RFC 9000 §4.2).
inline fn calc_advertised_window_candidate(base: u64, window_size: u64) -> u64 {
    let candidate = base + window_size;
    if candidate < base || candidate > rfc::QUIC_VARINT_MAX {
        return rfc::QUIC_VARINT_MAX;
    }
    return candidate;
}

// Computes flow control window renewal trigger threshold (RFC 9000 §4.2).
inline fn calc_window_renewal_threshold(window_size: u64) -> u64 {
    if window_size == 0 { return 0; }
    return max(1, window_size >> 1);
}

// Safely advances consumed byte counter with arithmetic wrap protection (RFC 9000 §4.1).
inline fn calc_safe_accumulate_bytes(current: u64, delta: u64) -> u64 {
    let next = current + delta;
    if next < current {
        return current;
    }
    return next;
}

// ---- Stream & Stream Table Internal Helpers ------------------------------

inline fn quic_stream_type(id: u64) -> quic::QuicStreamType {
    let t = id & 0x03;
    if t == 0 { return quic::QuicStreamType.ClientBidi; }
    if t == 1 { return quic::QuicStreamType.ServerBidi; }
    if t == 2 { return quic::QuicStreamType.ClientUni; }
    return quic::QuicStreamType.ServerUni;
}

inline fn quic_stream_can_send(id: u64, role: quic::QuicRole) -> bool {
    let t = id & 0x03;
    if t <= 1 { return true; } // Bidi: both endpoints can send
    if role == quic::QuicRole.Client {
        return t == 2; // Client can only send on ClientUni
    }
    return t == 3; // Server can only send on ServerUni
}

inline fn quic_stream_can_recv(id: u64, role: quic::QuicRole) -> bool {
    let t = id & 0x03;
    if t <= 1 { return true; } // Bidi: both endpoints can receive
    if role == quic::QuicRole.Client {
        return t == 3; // Client can receive on ServerUni
    }
    return t == 2; // Server can receive on ClientUni
}

fn new_quic_role_stream(stream_id: u64, role: quic::QuicRole, max_recv_flow: u64 = 65536) -> quic::QuicStream {
    let stype = quic_stream_type(stream_id);
    let can_recv = quic_stream_can_recv(stream_id, role);
    return quic::QuicStream {
        stream_id:     stream_id,
        stream_type:   stype,
        can_recv:      can_recv,
        recv_max_data: if can_recv { max_recv_flow } else { 0 },
    };
}

inline fn is_within_limit(offset: u64, len: u64, limit: u64) -> bool {
    if offset > limit { return false; }
    let rem = limit - offset;
    return rem >= len;
}

// Validates final size invariants upon receiving FIN or RESET_STREAM (RFC 9000 Section 4.5).
inline fn validate_recv_final_size(
    has_final:         bool,
    established_final: u64,
    new_final:         u64,
    bytes_recv:        u64,
    consumed:          u64,
) -> bool {
    if has_final {
        return established_final == new_final;
    }
    if new_final < bytes_recv { return false; }
    if new_final < consumed { return false; }
    return true;
}

inline fn record_stream_recv_range(s: quic::QuicStream&, start: u64, end: u64) -> bool {
    guard start < end else { return true; }
    var cur_s = start;
    var cur_e = end;
    var i: i64 = 0;
    while i < s.recv_ranges.len {
        let it = s.recv_ranges[i];
        if cur_e < it.start {
            guard s.recv_ranges.len < s.recv_ranges.cap else { return false; }
            s.recv_ranges.insert_at(i, quic::Interval { start: cur_s, end: cur_e });
            break;
        }
        if cur_s > it.end {
            i = i + 1;
            continue;
        }
        cur_s = min(cur_s, it.start);
        cur_e = max(cur_e, it.end);
        s.recv_ranges.remove_at(i);
    }
    if i == s.recv_ranges.len {
        guard s.recv_ranges.try_push(quic::Interval { start: cur_s, end: cur_e }) else { return false; }
    }
    if s.recv_ranges.len > 0 && s.recv_ranges[0].start == 0 {
        s.contiguous_recv_bytes = s.recv_ranges[0].end;
    }
    return true;
}

// Helper to determine if a stream was initiated by peer (RFC 9000 §2.1).
inline fn is_peer_initiated_stream(stream_id: u64, role: quic::QuicRole) -> bool {
    let init_bit = stream_id & 1;
    if role == quic::QuicRole.Server {
        return init_bit == 0;
    }
    return init_bit == 1;
}

// Validates stream ordinal against configured peer stream limits (RFC 9000 Section 4.6).
inline fn validate_peer_stream_limit(tbl: const quic::QuicStreamTable&, stream_id: u64) -> bool {
    guard is_peer_initiated_stream(stream_id, tbl.role) else { return true; }
    let stream_idx = stream_id >> 2;
    if (stream_id & 2) != 0 {
        return stream_idx < tbl.max_streams_uni;
    }
    return stream_idx < tbl.max_streams_bidi;
}

// Appends and initializes new stream into table.
inline fn quic_table_insert_stream(
    tbl:               quic::QuicStreamTable&,
    stream_id:         u64,
    default_recv_flow: u64,
) -> i32 {
    let new_idx = tbl.streams.len as i32;
    let st = new_quic_role_stream(stream_id, tbl.role, default_recv_flow);
    tbl.streams.push(st);
    return new_idx;
}

inline fn sweep_retired_contiguous_ordinals(tbl: quic::QuicStreamTable&, stype: i64) {
    while true {
        let target_id = core::shl_sat_u64(tbl.retired_contiguous_ord[stype], 2) | (stype as u64);
        var found_idx: i64 = -1;
        for i in tbl.evicted_closed_ids.len {
            if tbl.evicted_closed_ids[i] == target_id {
                found_idx = i;
                break;
            }
        }
        guard found_idx >= 0 else { return; }
        tbl.evicted_closed_ids.remove_at(found_idx);
        tbl.retired_contiguous_ord[stype] = core::add_sat_u64(tbl.retired_contiguous_ord[stype], 1);
    }
}

// Records an evicted terminal stream ID so late retransmissions cannot re-open it even after >64 evictions.
inline fn record_evicted_closed_stream(tbl: quic::QuicStreamTable&, stream_id: u64) {
    let stype = (stream_id & 3) as i64;
    let ord = stream_id >> 2;
    if ord < tbl.retired_contiguous_ord[stype] {
        return;
    }
    if ord == tbl.retired_contiguous_ord[stype] {
        tbl.retired_contiguous_ord[stype] = core::add_sat_u64(ord, 1);
        sweep_retired_contiguous_ordinals(tbl, stype);
        return;
    }
    for i in tbl.evicted_closed_ids.len {
        if tbl.evicted_closed_ids[i] == stream_id {
            return;
        }
    }
    if tbl.evicted_closed_ids.len == tbl.evicted_closed_ids.cap {
        tbl.evicted_closed_ids.remove_at(0);
    }
    tbl.evicted_closed_ids.push(stream_id);
}

// Advances the local stream counter by 4 according to RFC 9000 stream ID rules.
inline fn advance_stream_counter(tbl: quic::QuicStreamTable&, is_bidi: bool) -> u64 {
    if is_bidi {
        let sid = tbl.next_local_bidi_id;
        tbl.next_local_bidi_id = sid + 4;
        return sid;
    }
    let sid = tbl.next_local_uni_id;
    tbl.next_local_uni_id = sid + 4;
    return sid;
}
