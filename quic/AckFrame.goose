// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC ACK Framing, Optimistic ACK Defense, RTT Estimation & PTO Engine (RFC 9000, RFC 9002).
// Implements ACK/ACK_ECN codec, OACK validation (ANRW 2025), RTT estimators,
// packet/time threshold loss detection, and 5-priority PTO state machine.
namespace quic;

import std;
import core from "..";
import .packet;
import .internal;

// ---- packet number spaces and data types (rfc 9002 section 6.2.1) -------

enum PnSpaceId {
    Initial,
    Handshake,
    ApplicationData,
}

enum QuicEcnState {
    Testing,
    Unknown,
    Capable,
    Failed,
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
    ecn_marked:    bool = false,
}

struct PnSpaceState {
    space_id:                      PnSpaceId             = PnSpaceId.Initial,
    largest_sent_pn:               u64                   = 0,
    has_sent_packets:              bool                  = false,
    largest_acked_pn:              u64                   = 0,
    largest_acked_ect0:            u64                   = 0,
    largest_acked_ect1:            u64                   = 0,
    largest_acked_ce:              u64                   = 0,
    tx_ect0_sent:                  u64                   = 0,
    ecn_state:                     QuicEcnState          = QuicEcnState.Testing,
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
fn install_keys(
    space:        PnSpaceState&,
    hp_key:       const u8[:],
    aead_key:     const u8[:],
    aead_iv:      const u8[:],
    cipher_suite: u16 = 0x1301,
) -> bool {
    guard hp_key.len <= space.hp_key.cap
        && aead_key.len <= space.aead_key.cap
        && aead_iv.len <= space.aead_iv.cap else {
        return false;
    }
    guard space.hp_key.try_set(hp_key)
        && space.aead_key.try_set(aead_key)
        && space.aead_iv.try_set(aead_iv) else {
        return false;
    }
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
fn encode_ack_frame<B>(ack: const AckFrame&, out: B&) -> bool {
    guard ack.largest_acked >= ack.first_ack_range else { return false; }
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    let ftype = if ack.is_ecn { rfc::QUIC_FRAME_ACK_ECN } else { rfc::QUIC_FRAME_ACK };
    guard encode_varint(ftype, out)
        && encode_varint(ack.largest_acked, out)
        && encode_varint(ack.ack_delay, out)
        && encode_varint(ack.ranges.len as u64, out)
        && encode_varint(ack.first_ack_range, out) else {
        return false;
    }

    // RFC 9000 Section 19.3.1: ACK Ranges - Validate monotonically descending non-overlapping ACK ranges.
    var cur_smallest = core::sub_sat_u64(ack.largest_acked, ack.first_ack_range);
    for i in ack.ranges.len {
        let iv, ok_iv = quic_internal::step_descending_ack_range(
            cur_smallest,
            ack.ranges[i].gap,
            ack.ranges[i].ack_range,
        );
        guard ok_iv else { return false; }
        cur_smallest = iv.smallest;
        guard encode_varint(ack.ranges[i].gap, out)
            && encode_varint(ack.ranges[i].ack_range, out) else {
            return false;
        }
    }

    if ack.is_ecn {
        guard encode_varint(ack.ect0_count, out)
            && encode_varint(ack.ect1_count, out)
            && encode_varint(ack.ecn_ce_count, out) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// Decodes an ACK or ACK_ECN frame from wire buffer, returning the frame, next offset, and success status.
//
// Example:
//   src = [0x02, 0x05, 0x00, 0x00, 0x00], offset = 0
//   returns: AckFrame { largest_acked: 5 }, next_offset = 5, ok = true
fn decode_ack_frame(src: const u8[:], offset: u64) -> AckFrame, u64, bool {
    var cur = offset;
    let ftype, next_cur0, ok0 = decode_varint(src, cur);
    guard ok0 && (ftype == rfc::QUIC_FRAME_ACK || ftype == rfc::QUIC_FRAME_ACK_ECN) else {
        return AckFrame {}, offset, false;
    }
    cur = next_cur0;

    let largest_acked, next_cur1, ok1 = decode_varint(src, cur);
    guard ok1 else { return AckFrame {}, offset, false; }
    cur = next_cur1;

    let ack_delay, next_cur2, ok2 = decode_varint(src, cur);
    guard ok2 else { return AckFrame {}, offset, false; }
    cur = next_cur2;

    let range_cnt, next_cur3, ok3 = decode_varint(src, cur);
    guard ok3 && range_cnt <= rfc::QUIC_VARINT_MAX else { return AckFrame {}, offset, false; }
    cur = next_cur3;

    let first_range, next_cur4, ok4 = decode_varint(src, cur);
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

    guard quic_internal::decode_ack_frame_ranges(src, cur, range_cnt, largest_acked, first_range, ack) else {
        return AckFrame {}, offset, false;
    }

    if ack.is_ecn {
        let e0, next_cur_e0, oke0 = decode_varint(src, cur);
        guard oke0 else { return AckFrame {}, offset, false; }
        cur = next_cur_e0;
        let e1, next_cur_e1, oke1 = decode_varint(src, cur);
        guard oke1 else { return AckFrame {}, offset, false; }
        cur = next_cur_e1;
        let ce, next_cur_ce, okce = decode_varint(src, cur);
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
        first_ack_range: core::sub_sat_u64(largest, ranges[0].smallest),
        ..
    };

    var prev_smallest = ranges[0].smallest;
    for i in 1..ranges.len {
        let cur_range = ranges[i];
        guard prev_smallest >= 2 && core::sub_sat_u64(prev_smallest, 2) >= cur_range.largest else {
            return AckFrame {}, false;
        }
        let gap = core::sub_sat_u64(core::sub_sat_u64(prev_smallest, 2), cur_range.largest);
        guard cur_range.largest >= cur_range.smallest else { return AckFrame {}, false; }
        let rlen = core::sub_sat_u64(cur_range.largest, cur_range.smallest);
        guard ack.ranges.try_push(AckRange { gap: gap, ack_range: rlen }) else { return AckFrame {}, false; }
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
//   returns: ok = true, out = [AckInterval { smallest: 8, largest: 10 }]
fn parse_and_validate_ack<B>(
    space: const PnSpaceState&,
    ack:   const AckFrame&,
    out:   B&,
) -> bool {
    guard space.has_sent_packets else { return false; }
    guard ack.largest_acked <= space.largest_sent_pn else { return false; } // OACK forward attack!
    guard ack.largest_acked >= ack.first_ack_range else { return false; }   // Underflow!

    out.clear();
    let first_smallest = core::sub_sat_u64(ack.largest_acked, ack.first_ack_range);
    guard out.try_push(AckInterval { smallest: first_smallest, largest: ack.largest_acked }) else {
        out.clear();
        return false;
    }

    var cur_smallest = first_smallest;
    for i in ack.ranges.len {
        let r = ack.ranges[i];
        let iv, ok_iv = quic_internal::step_descending_ack_range(cur_smallest, r.gap, r.ack_range);
        guard ok_iv && out.try_push(iv) else {
            out.clear();
            return false;
        }
        cur_smallest = iv.smallest;
    }
    return true;
}

// Records received packet number into descending non-overlapping interval set.
fn record_received_pn(ranges: AckInterval[..64]&, pn: u64) -> bool {
    guard pn <= rfc::QUIC_MAX_PN else { return false; }
    var i: i64 = 0;
    while i < ranges.len {
        let r = ranges[i];
        let next_above = core::add_sat_u64(r.largest, 1);
        if pn > next_above {
            if ranges.len >= ranges.cap {
                ranges.pop();
            }
            ranges.insert_at(i, AckInterval { smallest: pn, largest: pn });
            return true;
        }
        if pn == next_above {
            ranges[i].largest = pn;
            // Check if merges with preceding range
            if i > 0 && ranges[i - 1].smallest == core::add_sat_u64(pn, 1) {
                ranges[i - 1].smallest = ranges[i].smallest;
                ranges.remove_at(i);
            }
            return true;
        }
        if pn >= r.smallest && pn <= r.largest {
            return true; // Duplicate packet
        }
        if core::add_sat_u64(pn, 1) == r.smallest {
            ranges[i].smallest = pn;
            // Check if merges with following range
            let next_i = core::add_sat_i64(i, 1);
            if next_i < ranges.len && core::add_sat_u64(ranges[next_i].largest, 1) == pn {
                ranges[i].smallest = ranges[next_i].smallest;
                ranges.remove_at(next_i);
            }
            return true;
        }
        i = core::add_sat_i64(i, 1);
    }
    if ranges.len >= ranges.cap {
        return true;
    }
    let _ = ranges.try_push(AckInterval { smallest: pn, largest: pn });
    return true;
}

// ---- rtt estimation (rfc 9002 section 5.3) --------------------------------

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
        rtt.rttvar_us = latest_rtt >> 1;
        rtt.first_sample_time_us = max(now_us, 1);
        return;
    }

    rtt.min_rtt_us = min(rtt.min_rtt_us, latest_rtt);

    var eff_delay: u64 = 0;
    if handshake_confirmed {
        eff_delay = min(ack_delay, rtt.max_ack_delay_us);
    }

    var adjusted_rtt = latest_rtt;
    if latest_rtt >= core::add_sat_u64(rtt.min_rtt_us, eff_delay) {
        adjusted_rtt = core::sub_sat_u64(latest_rtt, eff_delay);
    }

    let diff = quic_internal::rtt_abs_diff(rtt.smoothed_rtt_us, adjusted_rtt);
    rtt.rttvar_us = core::add_sat_u64(core::mul_sat_u64(rtt.rttvar_us, 3), diff) >> 2;
    rtt.smoothed_rtt_us = core::add_sat_u64(core::mul_sat_u64(rtt.smoothed_rtt_us, 7), adjusted_rtt) >> 3;
}

// ---- packet & time threshold loss detection (rfc 9002 section 6.1) -------

// Validates ECN counts on an incoming ACK/ACK_ECN frame per RFC 9000 §13.4.2.1 and Appendix A.4.
// Returns `(newly_acked_ce_count, ecn_ok)`. Transitions `space.ecn_state` to `Failed` on mangling/bleaching.
fn validate_ecn(
    space:          PnSpaceState&,
    ack:            const AckFrame&,
    ecn_acked_pkts: u64,
) -> u64, bool {
    if space.ecn_state == QuicEcnState.Failed {
        return 0, false;
    }
    if !ack.is_ecn {
        if ecn_acked_pkts > 0 {
            space.ecn_state = QuicEcnState.Failed;
            return 0, false;
        }
        return 0, true;
    }
    if ack.ect0_count < space.largest_acked_ect0
        || ack.ect1_count < space.largest_acked_ect1
        || ack.ecn_ce_count < space.largest_acked_ce {
        space.ecn_state = QuicEcnState.Failed;
        return 0, false;
    }
    let ect0_delta = core::sub_sat_u64(ack.ect0_count, space.largest_acked_ect0);
    let ce_delta = core::sub_sat_u64(ack.ecn_ce_count, space.largest_acked_ce);
    let total_delta = core::add_sat_u64(ect0_delta, ce_delta);
    if total_delta < ecn_acked_pkts || ack.ect1_count > space.largest_acked_ect1 {
        space.ecn_state = QuicEcnState.Failed;
        return 0, false;
    }
    if space.tx_ect0_sent > 0 && ack.ect0_count > space.tx_ect0_sent {
        space.ecn_state = QuicEcnState.Failed;
        return 0, false;
    }
    space.largest_acked_ect0 = ack.ect0_count;
    space.largest_acked_ect1 = ack.ect1_count;
    space.largest_acked_ce = ack.ecn_ce_count;
    if total_delta > 0 && space.ecn_state != QuicEcnState.Capable {
        space.ecn_state = QuicEcnState.Capable;
    }
    return ce_delta, true;
}

// Detects and removes lost packets in pn_space using packet and time thresholds in a single pass.
fn detect_lost_packets<B>(
    space:  PnSpaceState&,
    rtt:    const RttState&,
    now_us: u64,
    out:    B&,
) -> bool {
    guard space.has_acked_packets else { return true; }
    space.loss_time_us = 0;

    let loss_delay = quic_internal::calc_space_loss_delay(rtt);
    let lost_send_time = core::sub_sat_u64(now_us, loss_delay);

    var write_idx: u64 = 0;
    for i in space.sent_packets.len {
        let pkt .= space.sent_packets[i];
        if quic_internal::is_sent_packet_lost(pkt, space.largest_acked_pn, lost_send_time) {
            if !out.try_push(pkt) {
                quic_internal::compact_remaining_sent_packets(space, i, write_idx);
                return false;
            }
        } else {
            quic_internal::update_space_next_loss_time(space, pkt, loss_delay);
            if (write_idx as i64) != i {
                space.sent_packets[write_idx as i64] = pkt;
            }
            write_idx = core::add_sat_u64(write_idx, 1);
        }
    }
    space.sent_packets.resize(write_idx as i64, SentPacketMeta { .. });
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

struct PtoContext {
    is_server:                      bool = false,
    is_amplification_limited:       bool = false,
    peer_completed_addr_validation: bool = false,
    handshake_confirmed:            bool = false,
}

// Computes probe timeout duration with exponential backoff (RFC 9002 Sec 6.2.1).
fn compute_pto_duration(rtt: const RttState&, pto_count: u32, is_app_data: bool) -> u64 {
    let var4 = max(core::mul_sat_u64(rtt.rttvar_us, 4), rfc::QUIC_TIMER_GRANULARITY_US);
    var dur = core::add_sat_u64(rtt.smoothed_rtt_us, var4);
    if is_app_data {
        dur = core::add_sat_u64(dur, rtt.max_ack_delay_us);
    }
    let shift = min(pto_count, 16);
    return core::shl_sat_u64(dur, shift);
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
    let loss_t, loss_sp = quic_internal::get_earliest_loss_time(spaces);
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
    let in_flight_count = quic_internal::count_in_flight_eliciting(spaces, ctx.handshake_confirmed);

    // Priority 3: Client Anti-deadlock PTO
    if !ctx.is_server && in_flight_count == 0 && !ctx.peer_completed_addr_validation {
        let dur = compute_pto_duration(rtt, pto_count, false);
        let sp = if spaces[1].has_sent_packets { PnSpaceId.Handshake } else { PnSpaceId.Initial };
        return PtoTimerDecision {
            mode:           PtoTimerMode.AntiDeadlock,
            target_time_us: core::add_sat_u64(now_us, dur),
            space_id:       sp,
        };
    }

    // Priority 4: Idle connection with completed address validation
    if in_flight_count == 0 && ctx.peer_completed_addr_validation {
        return PtoTimerDecision { mode: PtoTimerMode.None, .. };
    }

    // Priority 5: Standard PTO across active spaces
    let earliest_pto, target_sp = quic_internal::find_earliest_standard_pto(
        spaces,
        rtt,
        pto_count,
        ctx.handshake_confirmed,
    );
    if earliest_pto != 0 {
        return PtoTimerDecision {
            mode:           PtoTimerMode.StandardPto,
            target_time_us: earliest_pto,
            space_id:       target_sp,
        };
    }

    return PtoTimerDecision { mode: PtoTimerMode.None, .. };
}
