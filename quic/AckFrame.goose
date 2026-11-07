// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC ACK Framing, Optimistic ACK Defense, RTT Estimation & PTO Engine (RFC 9000, RFC 9002).
// Implements ACK/ACK_ECN codec, OACK validation (ANRW 2025), RTT estimators,
// packet/time threshold loss detection, and 5-priority PTO state machine.
namespace internal;

import std;
import core from "..";
import .packet;

// ---- packet number spaces and data types (rfc 9002 section 6.2.1) -------

enum PnSpaceId {
    Initial,
    Handshake,
    ApplicationData,
}

// ACK Range interval [smallest, largest], inclusive
struct AckInterval {
    smallest: u64 = 0,
    largest:  u64 = 0,
}

struct AckRange {
    gap:       u64 = 0,
    ack_range: u64 = 0,
}

// ACK / ACK_ECN Frame structure (RFC 9000 Section 19.3)
struct AckFrame {
    is_ecn:          bool           = false,
    largest_acked:   u64            = 0,
    ack_delay:       u64            = 0,
    first_ack_range: u64            = 0,
    ranges:          AckRange[..64] = [],
    ect0_count:      u64            = 0,
    ect1_count:      u64            = 0,
    ecn_ce_count:    u64            = 0,
}

struct SentPacketMeta {
    pn:            u64  = 0,
    time_sent_us:  u64  = 0,
    size_bytes:    u64  = 0,
    ack_eliciting: bool = false,
    in_flight:     bool = false,
}

struct PnSpaceState {
    space_id:                      PnSpaceId             = PnSpaceId.Initial,
    largest_sent_pn:               u64                   = 0,
    has_sent_packets:              bool                  = false,
    largest_acked_pn:              u64                   = 0,
    largest_acked_ce:              u64                   = 0,
    has_acked_packets:             bool                  = false,
    largest_recv_pn:               u64                   = 0,
    has_recv_packets:              bool                  = false,
    time_of_last_ack_eliciting_us: u64                   = 0,
    loss_time_us:                  u64                   = 0,
    sent_packets:                  SentPacketMeta[..128] = [],
    recv_ranges:                   AckInterval[..64]     = [],
    hp_key:                        u8[..32]              = [],
    aead_key:                      u8[..32]              = [],
    aead_iv:                       u8[..12]              = [],
    cipher_suite:                  u16                   = 0x1301,
    keys_installed:                bool                  = false,
}

// Installs cryptographic keys for a QUIC packet number space (RFC 9001 §5).
//
// Example:
//   space = PnSpaceState { .. }, hp_key = [1; 16], aead_key = [2; 32], aead_iv = [3; 12]
//   returns: true, space.keys_installed = true
fn quic_install_pn_space_keys(
    space:        PnSpaceState&,
    hp_key:       const u8[:],
    aead_key:     const u8[:],
    aead_iv:      const u8[:],
    cipher_suite: u16 = 0x1301,
) -> bool {
    guard hp_key.len <= space.hp_key.cap else { return false; }
    guard aead_key.len <= space.aead_key.cap else { return false; }
    guard aead_iv.len <= space.aead_iv.cap else { return false; }
    space.hp_key.clear();
    space.hp_key.append(hp_key);
    space.aead_key.clear();
    space.aead_key.append(aead_key);
    space.aead_iv.clear();
    space.aead_iv.append(aead_iv);
    space.cipher_suite = cipher_suite;
    space.keys_installed = true;
    return true;
}

struct RttState {
    latest_rtt_us:        u64 = 0,
    min_rtt_us:           u64 = 0,
    smoothed_rtt_us:      u64 = 333000, // kInitialRtt = 333 ms (RFC 9002 Sec 6.2.2)
    rttvar_us:            u64 = 166500, // kInitialRtt / 2
    max_ack_delay_us:     u64 = 25000,  // 25 ms default (RFC 9000 Sec 18.2)
    first_sample_time_us: u64 = 0,
}

// ---- ack frame encoder & decoder (rfc 9000 section 19.3) -----------------

// Encodes an ACK or ACK_ECN frame into wire VarInt format.
fn encode_ack_frame<B>(out: B&, ack: const AckFrame&) -> bool {
    let orig_len = out.len;
    let ftype = if ack.is_ecn { rfc::QUIC_FRAME_ACK_ECN } else { rfc::QUIC_FRAME_ACK };
    guard quic_encode_varint(out, ftype)
        && quic_encode_varint(out, ack.largest_acked)
        && quic_encode_varint(out, ack.ack_delay)
        && quic_encode_varint(out, ack.ranges.len as u64)
        && quic_encode_varint(out, ack.first_ack_range) else {
        out.resize(orig_len, 0);
        return false;
    }

    for i in ack.ranges.len {
        guard quic_encode_varint(out, ack.ranges[i].gap)
            && quic_encode_varint(out, ack.ranges[i].ack_range) else {
            out.resize(orig_len, 0);
            return false;
        }
    }

    if ack.is_ecn {
        guard quic_encode_varint(out, ack.ect0_count)
            && quic_encode_varint(out, ack.ect1_count)
            && quic_encode_varint(out, ack.ecn_ce_count) else {
            out.resize(orig_len, 0);
            return false;
        }
    }
    return true;
}

// Decodes sequential ACK gap and range fields.
//
// Example:
//   src = [0x00, 0x01], cur = 0, range_cnt = 1
//   returns: ok = true, cur = 2
fn decode_ack_ranges(
    src:           const u8[:],
    cur:           u64&,
    range_cnt:     u64,
    largest_acked: u64,
    first_range:   u64,
    ack:           AckFrame&,
) -> bool {
    var cur_smallest = largest_acked - first_range;
    var r_idx: u64 = 0;
    while r_idx < range_cnt {
        let gap, next_cur_g, okg = quic_decode_varint(src, cur);
        guard okg else { return false; }
        cur = next_cur_g;
        let rlen, next_cur_r, okr = quic_decode_varint(src, cur);
        guard okr else { return false; }
        cur = next_cur_r;

        // RFC 9000 §19.3.1: Enforce descending bounds and avoid underflow
        guard cur_smallest >= 2 && (cur_smallest - 2) >= gap else { return false; }
        let cur_largest = cur_smallest - gap - 2;
        guard cur_largest >= rlen else { return false; }
        cur_smallest = cur_largest - rlen;

        guard ack.ranges.len < ack.ranges.cap else { return false; }
        ack.ranges.push(AckRange { gap: gap, ack_range: rlen });
        r_idx++;
    }
    return true;
}

// Decodes an ACK or ACK_ECN frame from wire buffer, returning the frame, next offset, and success status.
//
// Example:
//   src = [0x02, 0x05, 0x00, 0x00, 0x00], offset = 0
//   returns: AckFrame { largest_acked: 5 }, next_offset = 5, ok = true
fn decode_ack_frame(src: const u8[:], offset: u64) -> AckFrame, u64, bool {
    var cur = offset;
    let ftype, next_cur0, ok0 = quic_decode_varint(src, cur);
    guard ok0 && (ftype == rfc::QUIC_FRAME_ACK || ftype == rfc::QUIC_FRAME_ACK_ECN) else {
        return AckFrame {}, offset, false;
    }
    cur = next_cur0;

    let largest_acked, next_cur1, ok1 = quic_decode_varint(src, cur);
    guard ok1 else { return AckFrame {}, offset, false; }
    cur = next_cur1;

    let ack_delay, next_cur2, ok2 = quic_decode_varint(src, cur);
    guard ok2 else { return AckFrame {}, offset, false; }
    cur = next_cur2;

    let range_cnt, next_cur3, ok3 = quic_decode_varint(src, cur);
    guard ok3 && range_cnt <= 64 else { return AckFrame {}, offset, false; }
    cur = next_cur3;

    let first_range, next_cur4, ok4 = quic_decode_varint(src, cur);
    guard ok4 else { return AckFrame {}, offset, false; }
    cur = next_cur4;

    // RFC 9000 §19.3.1: Largest Acknowledged MUST be >= First ACK Range
    guard largest_acked >= first_range else { return AckFrame {}, offset, false; }

    var ack = AckFrame {
        is_ecn:          (ftype == rfc::QUIC_FRAME_ACK_ECN),
        largest_acked:   largest_acked,
        ack_delay:       ack_delay,
        first_ack_range: first_range,
        ..
    };

    guard range_cnt <= (ack.ranges.cap as u64) else { return AckFrame {}, offset, false; }
    guard decode_ack_ranges(src, cur, range_cnt, largest_acked, first_range, ack) else {
        return AckFrame {}, offset, false;
    }

    if ack.is_ecn {
        let e0, next_cur_e0, oke0 = quic_decode_varint(src, cur);
        guard oke0 else { return AckFrame {}, offset, false; }
        cur = next_cur_e0;
        let e1, next_cur_e1, oke1 = quic_decode_varint(src, cur);
        guard oke1 else { return AckFrame {}, offset, false; }
        cur = next_cur_e1;
        let ce, next_cur_ce, okce = quic_decode_varint(src, cur);
        guard okce else { return AckFrame {}, offset, false; }
        cur = next_cur_ce;
        ack.ect0_count = e0;
        ack.ect1_count = e1;
        ack.ecn_ce_count = ce;
    }
    return ack, cur, true;
}

// Converts a list of received packet intervals into an AckFrame representation.
//
// Example:
//   ranges = [AckInterval { smallest: 5, largest: 10 }], ack_delay = 0
//   returns: AckFrame { largest_acked: 10, first_ack_range: 5 }, ok = true
fn build_ack_frame(ranges: const AckInterval[..64]&, ack_delay: u64, is_ecn: bool = false) -> AckFrame, bool {
    guard ranges.len > 0 else { return AckFrame {}, false; }
    let largest = ranges[0].largest;
    guard largest >= ranges[0].smallest else { return AckFrame {}, false; }

    var ack = AckFrame {
        is_ecn:          is_ecn,
        largest_acked:   largest,
        ack_delay:       ack_delay,
        first_ack_range: largest - ranges[0].smallest,
        ..
    };

    var prev_smallest = ranges[0].smallest;
    for i in 1..ranges.len {
        let cur_range = ranges[i];
        guard prev_smallest >= 2 && (prev_smallest - 2) >= cur_range.largest else { return AckFrame {}, false; }
        let gap = prev_smallest - cur_range.largest - 2;
        guard cur_range.largest >= cur_range.smallest else { return AckFrame {}, false; }
        let rlen = cur_range.largest - cur_range.smallest;
        ack.ranges.push(AckRange { gap: gap, ack_range: rlen });
        prev_smallest = cur_range.smallest;
    }
    return ack, true;
}

// ---- optimistic ack (oack) validation & interval extraction ---------------

// Validates ACK against sent state to defeat Optimistic ACK attacks (ANRW 2025).
// Checks for forward-dated packet numbers, underflow, and descending consistency.
//
// Example:
//   space.largest_sent_pn = 10, ack = AckFrame { largest_acked: 10, first_ack_range: 2 }
//   returns: ok = true, out_intervals = [AckInterval { smallest: 8, largest: 10 }]
fn parse_and_validate_ack<B>(
    space:         const PnSpaceState&,
    ack:           const AckFrame&,
    out_intervals: B&,
) -> bool {
    guard space.has_sent_packets else { return false; }
    guard ack.largest_acked <= space.largest_sent_pn else { return false; } // OACK forward attack!
    guard ack.largest_acked >= ack.first_ack_range else { return false; }   // Underflow!

    out_intervals.clear();
    let first_smallest = ack.largest_acked - ack.first_ack_range;
    guard out_intervals.len < out_intervals.cap else { return false; }
    out_intervals.push(AckInterval { smallest: first_smallest, largest: ack.largest_acked });

    var cur_smallest = first_smallest;
    for i in ack.ranges.len {
        let r = ack.ranges[i];
        guard cur_smallest >= 2 && (cur_smallest - 2) >= r.gap else {
            out_intervals.clear();
            return false;
        }
        let cur_largest = cur_smallest - r.gap - 2;
        guard cur_largest >= r.ack_range else {
            out_intervals.clear();
            return false;
        }
        cur_smallest = cur_largest - r.ack_range;

        guard out_intervals.len < out_intervals.cap else {
            out_intervals.clear();
            return false;
        }
        out_intervals.push(AckInterval { smallest: cur_smallest, largest: cur_largest });
    }
    return true;
}

// Records received packet number into descending non-overlapping interval set.
fn record_received_pn(ranges: AckInterval[..64]&, pn: u64) -> bool {
    guard pn <= rfc::QUIC_MAX_PN else { return false; }
    var i = 0;
    while i < ranges.len {
        let r = ranges[i];
        if pn > r.largest + 1 {
            if ranges.len >= ranges.cap {
                ranges.pop();
            }
            ranges.insert_at(i, AckInterval { smallest: pn, largest: pn });
            return true;
        }
        if pn == r.largest + 1 {
            ranges[i].largest = pn;
            // Check if merges with preceding range
            if i > 0 && ranges[i - 1].smallest == pn + 1 {
                ranges[i - 1].smallest = ranges[i].smallest;
                ranges.remove_at(i);
            }
            return true;
        }
        if pn >= r.smallest && pn <= r.largest {
            return true; // Duplicate packet
        }
        if pn + 1 == r.smallest {
            ranges[i].smallest = pn;
            // Check if merges with following range
            if (i + 1) < ranges.len && ranges[i + 1].largest + 1 == pn {
                ranges[i].smallest = ranges[i + 1].smallest;
                ranges.remove_at(i + 1);
            }
            return true;
        }
        i++;
    }
    if ranges.len >= ranges.cap {
        return true;
    }
    ranges.push(AckInterval { smallest: pn, largest: pn });
    return true;
}

// ---- rtt estimation (rfc 9002 section 5.3) --------------------------------

inline fn rtt_abs_diff(a: u64, b: u64) -> u64 {
    return if a >= b { a - b } else { b - a };
}

// Updates smoothed_rtt, rttvar, and min_rtt upon receiving an ACK with ack-eliciting sample.
fn update_rtt(
    rtt:                 RttState&,
    latest_rtt:          u64,
    ack_delay:           u64,
    handshake_confirmed: bool,
    now_us:              u64,
) {
    rtt.latest_rtt_us = latest_rtt;

    if rtt.first_sample_time_us == 0 {
        rtt.min_rtt_us = latest_rtt;
        rtt.smoothed_rtt_us = latest_rtt;
        rtt.rttvar_us = latest_rtt / 2;
        rtt.first_sample_time_us = max(now_us, 1);
        return;
    }

    if latest_rtt < rtt.min_rtt_us {
        rtt.min_rtt_us = latest_rtt;
    }

    var eff_delay: u64 = 0;
    if handshake_confirmed {
        eff_delay = min(ack_delay, rtt.max_ack_delay_us);
    }

    var adjusted_rtt = latest_rtt;
    if latest_rtt >= core::add_sat_u64(rtt.min_rtt_us, eff_delay) {
        adjusted_rtt = latest_rtt - eff_delay;
    }

    let diff = rtt_abs_diff(rtt.smoothed_rtt_us, adjusted_rtt);
    rtt.rttvar_us = (3 * rtt.rttvar_us + diff) / 4;
    rtt.smoothed_rtt_us = (7 * rtt.smoothed_rtt_us + adjusted_rtt) / 8;
}

// ---- packet & time threshold loss detection (rfc 9002 section 6.1) -------

// Detects and removes lost packets in pn_space using packet and time thresholds.
fn detect_lost_packets<B>(
    space:    PnSpaceState&,
    rtt:      const RttState&,
    now_us:   u64,
    out_lost: B&,
) -> bool {
    guard space.has_acked_packets else { return true; }
    space.loss_time_us = 0;

    let max_rtt = if rtt.latest_rtt_us > rtt.smoothed_rtt_us {
        rtt.latest_rtt_us
    } else {
        rtt.smoothed_rtt_us
    };
    var loss_delay = (max_rtt * rfc::QUIC_LOSS_TIME_NUMERATOR) / rfc::QUIC_LOSS_TIME_DENOMINATOR;
    if loss_delay < rfc::QUIC_TIMER_GRANULARITY_US {
        loss_delay = rfc::QUIC_TIMER_GRANULARITY_US;
    }
    let lost_send_time = if now_us > loss_delay { now_us - loss_delay } else { 0 };

    var i = 0;
    while i < space.sent_packets.len {
        let pkt = space.sent_packets[i];
        if pkt.pn > space.largest_acked_pn {
            i++;
            continue;
        }

        let is_packet_threshold = space.largest_acked_pn >= pkt.pn + rfc::QUIC_LOSS_PACKET_THRESHOLD;
        let is_time_threshold = pkt.time_sent_us <= lost_send_time;

        if is_packet_threshold || is_time_threshold {
            guard out_lost.len < out_lost.cap else { return false; }
            out_lost.push(pkt);
            space.sent_packets.remove_at(i);
        } else {
            let next_loss_time = pkt.time_sent_us + loss_delay;
            if space.loss_time_us == 0 || next_loss_time < space.loss_time_us {
                space.loss_time_us = next_loss_time;
            }
            i++;
        }
    }
    return true;
}

// ---- 5-priority probe timeout (pto) state machine (rfc 9002 a.8/a.9) -----

enum PtoTimerMode {
    None,
    LossTime,
    AntiAmplification,
    AntiDeadlock,
    StandardPto,
}

struct PtoTimerDecision {
    mode:           PtoTimerMode = PtoTimerMode.None,
    target_time_us: u64          = 0,
    space_id:       PnSpaceId    = PnSpaceId.Initial,
}

// Finds earliest loss detection time across all active spaces (Priority 1).
fn get_earliest_loss_time(spaces: const PnSpaceState[3]&) -> u64, PnSpaceId {
    var earliest: u64 = 0;
    var space_id = PnSpaceId.Initial;

    for i in 3 {
        let lt = spaces[i].loss_time_us;
        if lt != 0 && (earliest == 0 || lt < earliest) {
            earliest = lt;
            space_id = spaces[i].space_id;
        }
    }
    return earliest, space_id;
}

// Computes probe timeout duration with exponential backoff (RFC 9002 Sec 6.2.1).
fn compute_pto_duration(rtt: const RttState&, pto_count: u32, is_app_data: bool) -> u64 {
    let var4 = if 4 * rtt.rttvar_us > rfc::QUIC_TIMER_GRANULARITY_US {
        4 * rtt.rttvar_us
    } else {
        rfc::QUIC_TIMER_GRANULARITY_US
    };
    var dur = rtt.smoothed_rtt_us + var4;
    if is_app_data {
        dur += rtt.max_ack_delay_us;
    }
    let shift = if pto_count < 16 { pto_count } else { 16 };
    return dur * ((1 as u64) << shift);
}

struct PtoContext {
    is_server:                      bool = false,
    is_amplification_limited:       bool = false,
    peer_completed_addr_validation: bool = false,
    handshake_confirmed:            bool = false,
}

fn count_in_flight_eliciting(spaces: const PnSpaceState[3]&, handshake_confirmed: bool = true) -> u64 {
    var count: u64 = 0;
    for s in 3 {
        if spaces[s].space_id == PnSpaceId.ApplicationData && !handshake_confirmed {
            continue;
        }
        for p in spaces[s].sent_packets.len {
            if spaces[s].sent_packets[p].ack_eliciting { count++; }
        }
    }
    return count;
}

fn find_earliest_standard_pto(
    spaces:              const PnSpaceState[3]&,
    rtt:                 const RttState&,
    pto_count:           u32,
    handshake_confirmed: bool,
    out_target_sp:       PnSpaceId&,
) -> u64 {
    var earliest_pto: u64 = 0;
    for s in 3 {
        let space = spaces[s];
        var space_has_eliciting = false;
        for p in space.sent_packets.len {
            if space.sent_packets[p].ack_eliciting { space_has_eliciting = true; break; }
        }
        if !space_has_eliciting { continue; }
        if space.space_id == PnSpaceId.ApplicationData && !handshake_confirmed {
            continue;
        }

        let is_app = space.space_id == PnSpaceId.ApplicationData;
        let dur = compute_pto_duration(rtt, pto_count, is_app);
        let t = space.time_of_last_ack_eliciting_us + dur;
        if earliest_pto == 0 || t < earliest_pto {
            earliest_pto = t;
            out_target_sp = space.space_id;
        }
    }
    return earliest_pto;
}

// Evaluates 5-tier PTO scheduling priority (RFC 9002 Section 6.2 & Appendix A.8).
fn evaluate_pto_timer(
    spaces:    const PnSpaceState[3]&,
    rtt:       const RttState&,
    pto_count: u32,
    now_us:    u64,
    ctx:       PtoContext,
) -> PtoTimerDecision {
    // Priority 1: Time threshold loss detection
    let loss_t, loss_sp = get_earliest_loss_time(spaces);
    if loss_t != 0 {
        return PtoTimerDecision {
            mode:           PtoTimerMode.LossTime,
            target_time_us: loss_t,
            space_id:       loss_sp,
        };
    }

    // Priority 2: Server anti-amplification limit
    if ctx.is_server && ctx.is_amplification_limited {
        return PtoTimerDecision { mode: PtoTimerMode.AntiAmplification, .. };
    }

    // Check ack-eliciting packets in flight across spaces
    let in_flight_count = count_in_flight_eliciting(spaces, ctx.handshake_confirmed);

    // Priority 3: Client Anti-deadlock PTO
    if !ctx.is_server && in_flight_count == 0 && !ctx.peer_completed_addr_validation {
        let dur = compute_pto_duration(rtt, pto_count, false);
        let sp = if spaces[1].has_sent_packets { PnSpaceId.Handshake } else { PnSpaceId.Initial };
        return PtoTimerDecision {
            mode:           PtoTimerMode.AntiDeadlock,
            target_time_us: now_us + dur,
            space_id:       sp,
        };
    }

    // Priority 4: Idle connection with completed address validation
    if in_flight_count == 0 && ctx.peer_completed_addr_validation {
        return PtoTimerDecision { mode: PtoTimerMode.None, .. };
    }

    // Priority 5: Standard PTO across active spaces
    var target_sp = PnSpaceId.Initial;
    let earliest_pto = find_earliest_standard_pto(spaces, rtt, pto_count, ctx.handshake_confirmed, target_sp);
    if earliest_pto != 0 {
        return PtoTimerDecision {
            mode:           PtoTimerMode.StandardPto,
            target_time_us: earliest_pto,
            space_id:       target_sp,
        };
    }

    return PtoTimerDecision { mode: PtoTimerMode.None, .. };
}
