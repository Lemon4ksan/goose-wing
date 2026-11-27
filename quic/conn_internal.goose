// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC connection recovery, ACK space tracking, and inbound frame dispatchers.
namespace quic_internal;

import std;
import core;
import .packet;
import .AckFrame;
import .bbr;
import .frames;
import .stream;
import .flow_control;
import .migration;
import .connection;
import tls.record;

inline fn quic_conn_is_closing_or_closed(state: quic::QuicConnState) -> bool {
    return state == quic::QuicConnState.Closing
        || state == quic::QuicConnState.Draining
        || state == quic::QuicConnState.Closed;
}

inline fn calc_amplification_limit(rx: u64) -> u64 {
    if rx > (0xFFFFFFFFFFFFFFFF / 3) {
        return 0xFFFFFFFFFFFFFFFF;
    }
    return rx * 3;
}

inline fn is_within_amplification_budget(sent: u64, extra: u64, limit: u64) -> bool {
    guard 0xFFFFFFFFFFFFFFFF - sent >= extra else { return false; }
    return (sent + extra) <= limit;
}

fn record_space_sent_packet(space: quic::PnSpaceState&, meta: const quic::SentPacketMeta&) {
    let was_empty = space.sent_packets.len == 0;
    guard space.sent_packets.try_push(meta) else { return; }
    space.has_sent_packets = true;
    if meta.pn > space.largest_sent_pn || was_empty {
        space.largest_sent_pn = meta.pn;
    }
    if meta.ack_eliciting {
        space.time_of_last_ack_eliciting_us = meta.time_sent_us;
    }
    if meta.ecn_marked {
        space.tx_ect0_sent = core::add_sat_u64(space.tx_ect0_sent, 1);
    }
}

fn record_space_recv_packet(space: quic::PnSpaceState&, pn: u64) {
    space.has_recv_packets = true;
    if pn > space.largest_recv_pn || space.recv_ranges.len == 0 {
        space.largest_recv_pn = pn;
    }
    let full_before = space.recv_ranges.len >= space.recv_ranges.cap;
    let old_tail_largest = if full_before {
        space.recv_ranges[space.recv_ranges.len - 1].largest
    } else {
        0
    };
    if quic::record_received_pn(space.recv_ranges, pn) && full_before && space.recv_ranges.len > 0 {
        let new_tail_smallest = space.recv_ranges[space.recv_ranges.len - 1].smallest;
        if new_tail_smallest > old_tail_largest {
            if !space.has_min_tracked_pn || old_tail_largest > space.min_tracked_pn {
                space.min_tracked_pn = old_tail_largest;
                space.has_min_tracked_pn = true;
            }
        }
    }
}

fn generate_space_ack(space: quic::PnSpaceState&) -> quic::AckFrame, bool {
    guard space.recv_ranges.len > 0 else { return quic::AckFrame { .. }, false; }
    return quic::build_ack_frame(space.recv_ranges, 0);
}

inline fn advance_ack_range_cursor(
    ranges:    const quic::AckInterval[..65]&,
    r_idx:     u64&,
    has_range: bool&,
    pn:        u64,
) {
    while has_range && ranges[r_idx as i64].largest < pn {
        if r_idx == 0 {
            has_range = false;
        } else {
            r_idx = core::sub_sat_u64(r_idx, 1);
        }
    }
}

inline fn record_acked_packet_stats(
    pkt:            const quic::SentPacketMeta&,
    largest_target: u64,
    is_new_largest: bool,
    now_us:         u64,
    acked_bytes:    u64&,
    largest_rtt_us: u64&,
    new_acked_pkts: u64&,
    ecn_acked_pkts: u64&,
    any_ack_el:     bool&,
) {
    new_acked_pkts = core::add_sat_u64(new_acked_pkts, 1);
    if pkt.ecn_marked { ecn_acked_pkts = core::add_sat_u64(ecn_acked_pkts, 1); }
    if pkt.in_flight { acked_bytes = core::add_sat_u64(acked_bytes, pkt.size_bytes); }
    if pkt.ack_eliciting { any_ack_el = true; }
    if pkt.pn == largest_target && is_new_largest {
        largest_rtt_us = core::sub_sat_u64(now_us, pkt.time_sent_us);
    }
}

// Marks packets matching `ranges` as acknowledged using a monotone two-pointer sweep,
// compacting `sent_packets` in-place and returning
// `(acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts, ecn_acked_pkts)`.
fn mark_acked_packets_in_space(
    space:  quic::PnSpaceState&,
    ranges: const quic::AckInterval[..65]&,
    now_us: u64,
) -> u64, u64, u64, u64, u64 {
    var acked_bytes:     u64 = 0;
    var largest_rtt_us:  u64 = 0;
    var in_flight_bytes: u64 = 0;
    var new_acked_pkts:  u64 = 0;
    var ecn_acked_pkts:  u64 = 0;
    var any_ack_el = false;

    let is_new_largest = !space.has_acked_packets || ranges[0].largest >= space.largest_acked_pn;
    if is_new_largest {
        space.largest_acked_pn = ranges[0].largest;
        space.has_acked_packets = true;
    }

    var has_range = ranges.len > 0;
    var r_idx = core::sub_sat_u64(ranges.len as u64, 1);
    var write_idx: u64 = 0;
    for i in space.sent_packets.len {
        let pkt .= space.sent_packets[i];
        advance_ack_range_cursor(ranges, r_idx, has_range, pkt.pn);
        if has_range && pkt.pn >= ranges[r_idx as i64].smallest {
            record_acked_packet_stats(
                pkt,
                ranges[0].largest,
                is_new_largest,
                now_us,
                acked_bytes,
                largest_rtt_us,
                new_acked_pkts,
                ecn_acked_pkts,
                any_ack_el,
            );
        } else {
            if pkt.in_flight { in_flight_bytes = core::add_sat_u64(in_flight_bytes, pkt.size_bytes); }
            if (write_idx as i64) != i {
                space.sent_packets[write_idx as i64] = pkt;
            }
            write_idx = core::add_sat_u64(write_idx, 1);
        }
    }
    space.sent_packets.resize(write_idx as i64, quic::SentPacketMeta { .. });
    let latest_rtt_us = if any_ack_el { largest_rtt_us } else { 0 };
    return acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts, ecn_acked_pkts;
}

fn calc_lost_bytes(lost_pkts: const quic::SentPacketMeta[..128]&) -> u64 {
    var lost_bytes: u64 = 0;
    for i in lost_pkts.len {
        if lost_pkts[i].in_flight {
            lost_bytes += lost_pkts[i].size_bytes;
        }
    }
    return lost_bytes;
}

inline fn update_bbr_sample_bw(bbr: quic::BbrState&, acked_bytes: u64, eff_rtt: u64) {
    if acked_bytes >= rfc::PMTU_BASE && eff_rtt > 0 {
        let sample_bw = (acked_bytes * 8000000) / eff_rtt;
        if sample_bw > bbr.bw_hi_bps {
            bbr.bw_hi_bps = sample_bw;
        }
    }
}

inline fn update_bbr_on_ack(
    conn:            quic::QuicConnection&,
    in_flight_bytes: u64,
    lost_bytes:      u64,
    acked_bytes:     u64,
    ecn_ce_count:    u64,
    new_acked_pkts:  u64,
    round_done:      bool,
) {
    if lost_bytes > 0 || ecn_ce_count > 0 {
        quic::on_congestion_signal(
            conn.bbr,
            in_flight_bytes,
            lost_bytes,
            acked_bytes,
            ecn_ce_count,
            new_acked_pkts,
        );
        quic::update_pacing_and_cwnd(conn.bbr, 0);
    } else if acked_bytes > 0 {
        if round_done {
            quic::advance_cycle(conn.bbr, true, acked_bytes);
        } else {
            quic::update_pacing_and_cwnd(conn.bbr, acked_bytes);
        }
    }
    pacer_set_rate(conn.pacer, conn.bbr.pacer.pacing_rate_bps);
}

// Processes a validated ACK frame in `space`, updating RTT, loss detection, and BBRv3 congestion control.
fn process_space_ack(
    conn:      quic::QuicConnection&,
    space:     quic::PnSpaceState&,
    ack_frame: const quic::AckFrame&,
    now_us:    u64,
    is_app:    bool,
) -> bool {
    var acked_ranges: quic::AckInterval[..65] = [];
    let ok = quic::parse_and_validate_ack(space, ack_frame, acked_ranges);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return false;
    }

    let acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts, ecn_acked_pkts =
        mark_acked_packets_in_space(space, acked_ranges, now_us);

    if new_acked_pkts > 0 && latest_rtt_us > 0 {
        let ack_delay_us = core::mul_sat_u64(ack_frame.ack_delay, 8);
        let confirmed = is_app
            && (conn.state == quic::QuicConnState.Established || conn.state == quic::QuicConnState.Handshake);
        quic::update_rtt(conn.rtt, latest_rtt_us, ack_delay_us, confirmed, now_us);
    }

    let eff_rtt = if latest_rtt_us > 0 { latest_rtt_us } else { conn.rtt.smoothed_rtt_us };
    update_bbr_sample_bw(conn.bbr, acked_bytes, eff_rtt);

    var lost_pkts: quic::SentPacketMeta[..128] = [];
    let _ = quic::detect_lost_packets(space, conn.rtt, now_us, lost_pkts);
    let lost_bytes = calc_lost_bytes(lost_pkts);

    let new_ecn_ce, ecn_ok = quic::validate_ecn(space, ack_frame, ecn_acked_pkts);
    let eff_ecn_ce = if ecn_ok { new_ecn_ce } else { 0 };

    quic::check_probe_rtt(conn.bbr, now_us, eff_rtt);
    let round_done = space.largest_acked_pn >= space.largest_sent_pn;
    update_bbr_on_ack(
        conn,
        in_flight_bytes,
        lost_bytes,
        acked_bytes,
        eff_ecn_ce,
        new_acked_pkts,
        round_done,
    );
    return true;
}

fn bind_initial_server_cids(conn: quic::QuicConnection&, hdr: const quic::QuicHeader&) {
    guard conn.role == quic::QuicRole.Server && conn.packets_rx == 1 else { return; }
    if conn.dcid.len == 0 {
        conn.dcid.append(hdr.scid[..]);
    }
    if conn.original_dcid.len == 0 {
        conn.original_dcid.append(hdr.dcid[..]);
    }
}

fn dispatch_packet_type(
    conn:    quic::QuicConnection&,
    hdr:     const quic::QuicHeader&,
    out_ack: quic::AckFrame&,
) -> quic::ProcessResult {
    guard !quic_conn_is_closing_or_closed(conn.state) else {
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    if hdr.header_type == quic::QuicHeaderType.Initial {
        record_space_recv_packet(conn.initial_space, hdr.packet_number);
        let ack, needs_ack = generate_space_ack(conn.initial_space);
        if needs_ack { out_ack = ack; }
        return quic::ProcessResult { handled: true, needs_ack: needs_ack };
    }

    if hdr.header_type == quic::QuicHeaderType.Handshake {
        if conn.state == quic::QuicConnState.Initial {
            conn.state = quic::QuicConnState.Handshake;
        }
        if conn.role == quic::QuicRole.Server {
            conn.validated_address = true;
        }
        record_space_recv_packet(conn.handshake_space, hdr.packet_number);
        let ack, needs_ack = generate_space_ack(conn.handshake_space);
        if needs_ack { out_ack = ack; }
        return quic::ProcessResult { handled: true, needs_ack: needs_ack };
    }

    if hdr.header_type == quic::QuicHeaderType.ZeroRtt {
        // RFC 9000 Section 12.3: Packet Numbers - 0-RTT packets share the Application Data PN space for duplicate suppression.
        record_space_recv_packet(conn.app_space, hdr.packet_number);
        return quic::ProcessResult { handled: true, needs_ack: false };
    }

    if hdr.header_type == quic::QuicHeaderType.OneRtt {
        if conn.state == quic::QuicConnState.Handshake || conn.state == quic::QuicConnState.Initial {
            conn.state = quic::QuicConnState.Established;
            conn.validated_address = true;
        }
        record_space_recv_packet(conn.app_space, hdr.packet_number);
        let ack, needs_ack = generate_space_ack(conn.app_space);
        if needs_ack { out_ack = ack; }
        return quic::ProcessResult { handled: true, needs_ack: needs_ack };
    }

    if hdr.header_type == quic::QuicHeaderType.VersionNegotiation {
        return quic::ProcessResult { handled: true, needs_ack: false };
    }

    return quic::ProcessResult { handled: false, needs_ack: false };
}

inline fn get_bounded_payload(
    dgram:       const u8[:],
    start:       i64,
    payload_len: u64,
    pn_len:      u8,
) -> u8[:] {
    let blen = (payload_len - pn_len) as i64;
    let end = start + blen;
    guard end <= dgram.len else { return dgram[..0]; }
    return dgram[start..end];
}

fn get_packet_payload(dgram: const u8[:], hdr: const quic::QuicHeader&) -> u8[:] {
    let start: i64 = hdr.header_len;
    guard start <= dgram.len else { return dgram[..0]; }
    if hdr.header_type != quic::QuicHeaderType.OneRtt {
        return get_bounded_payload(dgram, start, hdr.payload_length, hdr.pn_length);
    }
    return dgram[start..];
}

inline fn validate_stream_recv_final_size(
    s:          const quic::QuicStream&,
    end_offset: u64,
    fin:        bool,
) -> bool {
    if s.has_recv_final_size {
        if end_offset > s.recv_final_size || (fin && end_offset != s.recv_final_size) {
            return false;
        }
    }
    if fin && !s.has_recv_final_size {
        if end_offset < s.bytes_recv || end_offset < s.recv_consumed {
            return false;
        }
    }
    return true;
}

fn dispatch_stream_inbound(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if quic::is_evicted_closed_stream(conn.stream_table, frame.stream_id) {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }

    // RFC 9000 Section 19.8: STREAM Frames - Ingress STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let _, found = quic::find_stream(conn.stream_table, frame.stream_id);
        guard found else {
            quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
    }

    let idx, ok = quic::get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let end_offset = frame.offset + frame.length;
    guard validate_stream_recv_final_size(conn.stream_table.streams[idx], end_offset, frame.fin) else {
        quic::close(conn, rfc::QUIC_ERR_FINAL_SIZE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let prev_s_recv = conn.stream_table.streams[idx].bytes_recv;
    let prev_conn_recv = conn.flow_ctrl.bytes_recv_total;
    let fc_err, fc_ok = quic::record_recv_stream(
        conn.flow_ctrl,
        conn.stream_table.streams[idx],
        frame.offset,
        frame.length,
    );
    guard fc_ok else {
        quic::close(conn, fc_err);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let st_err, st_ok = quic::on_recv_stream_frame(
        conn.stream_table.streams[idx],
        frame.offset,
        frame.length,
        frame.fin,
    );
    guard st_ok else {
        conn.stream_table.streams[idx].bytes_recv = prev_s_recv;
        conn.flow_ctrl.bytes_recv_total = prev_conn_recv;
        quic::close(conn, st_err);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_reset_stream_inbound(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if quic::is_evicted_closed_stream(conn.stream_table, frame.stream_id) {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }

    // RFC 9000 §19.4: Ingress RESET_STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let _, found = quic::find_stream(conn.stream_table, frame.stream_id);
        guard found else {
            quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
    }

    let idx, ok = quic::get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let fc_err, fc_ok = quic::record_recv_reset(conn.flow_ctrl, conn.stream_table.streams[idx], frame.final_size);
    guard fc_ok else {
        quic::close(conn, fc_err);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let st_err, st_ok = quic::on_recv_reset(conn.stream_table.streams[idx], frame.error_code, frame.final_size);
    guard st_ok else {
        quic::close(conn, st_err);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_stop_sending_inbound(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    guard quic_stream_can_send(frame.stream_id, conn.role) else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if quic::is_evicted_closed_stream(conn.stream_table, frame.stream_id) {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }

    // RFC 9000 §19.5: Ingress STOP_SENDING frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let _, found = quic::find_stream(conn.stream_table, frame.stream_id);
        guard found else {
            quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
    }

    let idx, ok = quic::get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    let st_err, st_ok = quic::on_recv_stop_sending(conn.stream_table.streams[idx], frame.error_code, conn.role);
    guard st_ok else {
        quic::close(conn, st_err);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }

    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_max_stream_data_inbound(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    guard quic_stream_can_send(frame.stream_id, conn.role) else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if quic::is_evicted_closed_stream(conn.stream_table, frame.stream_id) {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    // RFC 9000 §19.10: Ingress MAX_STREAM_DATA frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let _, found = quic::find_stream(conn.stream_table, frame.stream_id);
        guard found else {
            quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
    }
    let idx, ok = quic::get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    quic::update_send_max_data(conn.stream_table.streams[idx], frame.max_data);
    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_stream_data_blocked_inbound(
    conn:  quic::QuicConnection&,
    frame: const quic::QuicFrame&,
) -> quic::ProcessResult {
    // RFC 9000 §19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only
    // stream MUST terminate the connection with error STREAM_STATE_ERROR."
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if quic::is_evicted_closed_stream(conn.stream_table, frame.stream_id) {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let _, found = quic::find_stream(conn.stream_table, frame.stream_id);
        guard found else {
            quic::close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
    }
    let _, ok = quic::get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic::close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_flow_control_inbound(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    if frame.frame_type == quic::QuicFrameType.MaxData {
        quic::update_remote_max_data(conn.flow_ctrl, frame.max_data);
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.MaxStreamData {
        return dispatch_max_stream_data_inbound(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.MaxStreamsBidi {
        let cur_lim = if conn.stream_table.has_remote_max_streams_bidi {
            conn.stream_table.remote_max_streams_bidi
        } else {
            conn.stream_table.max_streams_bidi
        };
        if !conn.stream_table.has_remote_max_streams_bidi || frame.max_data > cur_lim {
            conn.stream_table.remote_max_streams_bidi = frame.max_data;
            conn.stream_table.has_remote_max_streams_bidi = true;
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.MaxStreamsUni {
        let cur_lim = if conn.stream_table.has_remote_max_streams_uni {
            conn.stream_table.remote_max_streams_uni
        } else {
            conn.stream_table.max_streams_uni
        };
        if !conn.stream_table.has_remote_max_streams_uni || frame.max_data > cur_lim {
            conn.stream_table.remote_max_streams_uni = frame.max_data;
            conn.stream_table.has_remote_max_streams_uni = true;
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.StreamDataBlocked {
        return dispatch_stream_data_blocked_inbound(conn, frame);
    }
    return quic::ProcessResult { handled: true, needs_ack: true };
}

inline fn queue_pending_retire_cid(conn: quic::QuicConnection&, seq: u64) -> bool {
    for i in conn.pending_retire_cids.len {
        if conn.pending_retire_cids[i] == seq { return true; }
    }
    return conn.pending_retire_cids.try_push(seq);
}

inline fn evict_peer_reset_token_by_seq(conn: quic::QuicConnection&, seq: u64) {
    var i: i64 = 0;
    while i < conn.peer_reset_token_seqs.len && i < conn.peer_reset_tokens.len {
        if conn.peer_reset_token_seqs[i] == seq {
            conn.peer_reset_token_seqs.remove_at(i);
            conn.peer_reset_tokens.remove_at(i);
        } else {
            i += 1;
        }
    }
}

inline fn evict_peer_cids_prior_to(conn: quic::QuicConnection&, prior_to: u64) -> bool {
    var i: i64 = 0;
    while i < conn.peer_cid_seqs.len {
        if conn.peer_cid_seqs[i] < prior_to {
            let seq = conn.peer_cid_seqs[i];
            conn.peer_cid_seqs.remove_at(i);
            conn.peer_cids.remove_at(i);
            guard queue_pending_retire_cid(conn, seq) else { return false; }
        } else {
            i += 1;
        }
    }
    i = 0;
    while i < conn.peer_reset_token_seqs.len && i < conn.peer_reset_tokens.len {
        if conn.peer_reset_token_seqs[i] < prior_to {
            conn.peer_reset_token_seqs.remove_at(i);
            conn.peer_reset_tokens.remove_at(i);
        } else {
            i += 1;
        }
    }
    return true;
}

inline fn retire_peer_cid_seq(conn: quic::QuicConnection&, seq: u64) -> bool {
    evict_peer_reset_token_by_seq(conn, seq);
    var i: i64 = 0;
    while i < conn.peer_cid_seqs.len {
        if conn.peer_cid_seqs[i] == seq {
            conn.peer_cid_seqs.remove_at(i);
            conn.peer_cids.remove_at(i);
        } else {
            i += 1;
        }
    }
    return queue_pending_retire_cid(conn, seq);
}

inline fn find_peer_cid_by_seq(conn: const quic::QuicConnection&, seq: u64) -> i64 {
    for i in conn.peer_cid_seqs.len {
        if conn.peer_cid_seqs[i] == seq { return i; }
    }
    return -1;
}

inline fn register_peer_cid_and_token(
    conn:        quic::QuicConnection&,
    seq:         u64,
    cid_slice:   const u8[:],
    token_slice: const u8[:],
) -> bool {
    var dup_tok = false;
    for i in conn.peer_reset_tokens.len {
        if core::ct_eq_bytes(conn.peer_reset_tokens[i][..], token_slice) {
            dup_tok = true;
        }
    }
    if !dup_tok {
        if conn.peer_reset_tokens.len >= conn.peer_reset_tokens.cap {
            conn.peer_reset_tokens.remove_at(0);
            if conn.peer_reset_token_seqs.len > 0 { conn.peer_reset_token_seqs.remove_at(0); }
        }
        var tok: u8[16] = [0; 16];
        for i in 16 { tok[i] = token_slice[i]; }
        guard conn.peer_reset_tokens.try_push(tok) else { return false; }
        guard conn.peer_reset_token_seqs.try_push(seq) else { return false; }
    }
    var cid_copy: u8[..20] = [];
    guard cid_copy.try_set(cid_slice) else { return false; }
    guard conn.peer_cids.try_push(cid_copy) else { return false; }
    guard conn.peer_cid_seqs.try_push(seq) else { return false; }
    return true;
}

inline fn push_peer_reset_token(
    conn:        quic::QuicConnection&,
    seq:         u64,
    token_slice: const u8[:],
) -> bool {
    var tok: u8[16] = [0; 16];
    for i in 16 { tok[i] = token_slice[i]; }
    if conn.peer_reset_tokens.len >= conn.peer_reset_tokens.cap {
        conn.peer_reset_tokens.remove_at(0);
        if conn.peer_reset_token_seqs.len > 0 { conn.peer_reset_token_seqs.remove_at(0); }
    }
    return conn.peer_reset_tokens.try_push(tok) && conn.peer_reset_token_seqs.try_push(seq);
}

inline fn handle_new_connection_id_frame(
    conn:  quic::QuicConnection&,
    frame: const quic::QuicFrame&,
) -> quic::ProcessResult {
    // RFC 9000 Section 19.15: Zero-length DCID or retire_prior_to > sequence_number is PROTOCOL_VIOLATION.
    let seq = frame.stream_id;
    let retire_prior_to = frame.offset;
    guard conn.dcid.len > 0 && retire_prior_to <= seq else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    guard frame.length >= 1 && frame.length <= 20 && (frame.payload.len as u64) == frame.length + 16 else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    let cid_len = frame.length as i64;
    let cid_slice = frame.payload[..cid_len];
    let token_slice = frame.payload[cid_len..];

    if seq < conn.peer_retire_prior_to {
        guard queue_pending_retire_cid(conn, seq) else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if seq == conn.active_peer_cid_seq {
        guard cid_slice == conn.dcid[..] else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    let dup_idx = find_peer_cid_by_seq(conn, seq);
    if dup_idx >= 0 {
        guard conn.peer_cids[dup_idx][..] == cid_slice else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }

    var active_dcid_retired = false;
    if retire_prior_to > conn.peer_retire_prior_to {
        guard evict_peer_cids_prior_to(conn, retire_prior_to) else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        if conn.active_peer_cid_seq < retire_prior_to {
            active_dcid_retired = true;
            guard queue_pending_retire_cid(conn, conn.active_peer_cid_seq) else {
                quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
                return quic::ProcessResult { handled: false, needs_ack: false };
            }
        }
        conn.peer_retire_prior_to = retire_prior_to;
    }

    let eff_active_base: u64 = if active_dcid_retired { 0 } else { 1 };
    let new_total_cids = eff_active_base + (conn.peer_cids.len as u64) + 1;
    guard new_total_cids <= conn.active_connection_id_limit else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    if active_dcid_retired {
        guard conn.dcid.try_set(cid_slice) && push_peer_reset_token(conn, seq, token_slice) else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        conn.active_peer_cid_seq = seq;
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    guard register_peer_cid_and_token(conn, seq, cid_slice, token_slice) else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    return quic::ProcessResult { handled: true, needs_ack: true };
}

inline fn dispatch_conn_id_frame(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    if frame.frame_type == quic::QuicFrameType.NewConnectionId {
        return handle_new_connection_id_frame(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.RetireConnectionId {
        // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - Zero-length SCID or unissued sequence
        // number MUST be treated as PROTOCOL_VIOLATION.
        if conn.scid.len == 0 || frame.stream_id > (conn.alt_scids.len as u64) {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        evict_peer_reset_token_by_seq(conn, frame.stream_id);
        if frame.stream_id >= 1 {
            let alt_i = (frame.stream_id - 1) as i64;
            if alt_i >= 0 && alt_i < conn.alt_scids.len {
                conn.alt_scids[alt_i].clear();
            }
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_session_frame(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    if frame.frame_type == quic::QuicFrameType.ConnectionClose
        || frame.frame_type == quic::QuicFrameType.ConnectionCloseApp {
        // RFC 9000 Section 10.2.2: Draining Connection State - Receipt of CONNECTION_CLOSE enters Draining state.
        conn.close_code = frame.error_code;
        conn.state = quic::QuicConnState.Draining;
        return quic::ProcessResult { handled: true, needs_ack: false };
    }
    if frame.frame_type == quic::QuicFrameType.HandshakeDone {
        if conn.role == quic::QuicRole.Server {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        if !quic_conn_is_closing_or_closed(conn.state) {
            conn.state = quic::QuicConnState.Established;
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.NewToken {
        // RFC 9000 §19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt
        // of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
        if conn.role == quic::QuicRole.Server {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.PathChallenge {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.PathResponse {
        let ok = quic::on_path_response(conn.migration, frame.payload);
        if ok {
            quic::complete(conn.migration);
            conn.validated_address = true;
        }
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.NewConnectionId
        || frame.frame_type == quic::QuicFrameType.RetireConnectionId {
        return dispatch_conn_id_frame(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.DataBlocked
        || frame.frame_type == quic::QuicFrameType.StreamsBlockedBidi
        || frame.frame_type == quic::QuicFrameType.StreamsBlockedUni
        || frame.frame_type == quic::QuicFrameType.Datagram
        || frame.frame_type == quic::QuicFrameType.ImmediateAck
        || frame.frame_type == quic::QuicFrameType.AckFrequency {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    quic::close(conn, rfc::QUIC_ERR_FRAME_ENCODING);
    return quic::ProcessResult { handled: false, needs_ack: false };
}

// RFC 9000 Section 7.5: Cryptographic Message Buffering - Stage out-of-order CRYPTO ranges per
// epoch; close with CRYPTO_BUFFER_EXCEEDED only when buffering limits or offset bounds fail.
fn dispatch_crypto_inbound(
    conn:  quic::QuicConnection&,
    frame: const quic::QuicFrame&,
    htype: quic::QuicHeaderType,
) -> quic::ProcessResult {
    guard frame.payload.len > 0 else {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    var stream .= conn.app_crypto;
    if htype == quic::QuicHeaderType.Initial {
        stream .= conn.initial_crypto;
    } else if htype == quic::QuicHeaderType.Handshake {
        stream .= conn.handshake_crypto;
    }
    let _, ingested = tls::quic_crypto_stream_ingest(stream, frame.offset, frame.payload);
    guard ingested else {
        quic::close(conn, rfc::QUIC_ERR_CRYPTO_BUFFER_EXCEEDED);
        return quic::ProcessResult { handled: false, needs_ack: false };
    }
    return quic::ProcessResult { handled: true, needs_ack: true };
}

fn dispatch_inbound_frame(
    conn:  quic::QuicConnection&,
    frame: const quic::QuicFrame&,
    htype: quic::QuicHeaderType = quic::QuicHeaderType.OneRtt,
) -> quic::ProcessResult {
    if frame.frame_type == quic::QuicFrameType.Padding {
        return quic::ProcessResult { handled: true, needs_ack: false };
    }
    if frame.frame_type == quic::QuicFrameType.Ping {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.Ack || frame.frame_type == quic::QuicFrameType.AckEcn {
        return quic::ProcessResult { handled: true, needs_ack: false };
    }
    if frame.frame_type == quic::QuicFrameType.Crypto {
        return dispatch_crypto_inbound(conn, frame, htype);
    }
    if frame.frame_type == quic::QuicFrameType.Stream {
        return dispatch_stream_inbound(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.ResetStream {
        return dispatch_reset_stream_inbound(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.StopSending {
        return dispatch_stop_sending_inbound(conn, frame);
    }
    if frame.frame_type == quic::QuicFrameType.MaxData
        || frame.frame_type == quic::QuicFrameType.MaxStreamData
        || frame.frame_type == quic::QuicFrameType.StreamDataBlocked
        || frame.frame_type == quic::QuicFrameType.MaxStreamsBidi
        || frame.frame_type == quic::QuicFrameType.MaxStreamsUni {
        return dispatch_flow_control_inbound(conn, frame);
    }
    return dispatch_session_frame(conn, frame);
}

inline fn header_type_to_space_id(htype: quic::QuicHeaderType) -> quic::PnSpaceId {
    if htype == quic::QuicHeaderType.Initial {
        return quic::PnSpaceId.Initial;
    }
    if htype == quic::QuicHeaderType.Handshake {
        return quic::PnSpaceId.Handshake;
    }
    return quic::PnSpaceId.ApplicationData;
}

fn dispatch_inbound_ack_frame(
    conn:   quic::QuicConnection&,
    frame:  const quic::QuicFrame&,
    htype:  quic::QuicHeaderType,
    now_us: u64,
) -> bool {
    var ack_f = quic::AckFrame {
        is_ecn:          frame.frame_type == quic::QuicFrameType.AckEcn,
        largest_acked:   frame.offset,
        ack_delay:       frame.max_data,
        first_ack_range: frame.length,
        ..
    };
    if frame.payload.len > 0 {
        let decoded, _, ok = quic::decode_ack_frame(frame.payload, 0);
        guard ok else {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false;
        }
        ack_f = decoded;
    }
    let space_id = header_type_to_space_id(htype);
    var has_sent = conn.app_space.has_sent_packets;
    if space_id == quic::PnSpaceId.Initial {
        has_sent = conn.initial_space.has_sent_packets;
    } else if space_id == quic::PnSpaceId.Handshake {
        has_sent = conn.handshake_space.has_sent_packets;
    }
    guard has_sent else {
        quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return false;
    }
    return quic::on_ack(conn, ack_f, now_us, space_id);
}
