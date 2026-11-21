// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC connection packet/frame dispatchers, key derivation, AEAD, and HP helpers.
namespace quic_internal;

import std;
import core from "..";
import .packet;
import .packet_internal;
import .AckFrame;
import .bbr;
import .frames;
import .stream;
import .flow_control;
import .migration;
import .connection;
import tls.record;
import tls.key_schedule;

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
    quic::record_received_pn(space.recv_ranges, pn);
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
    if acked_bytes > 0 && eff_rtt > 0 {
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
        quic::update_pacing_and_cwnd(conn.bbr);
        quic::on_congestion_signal(
            conn.bbr,
            in_flight_bytes,
            lost_bytes,
            acked_bytes,
            ecn_ce_count,
            new_acked_pkts,
        );
    } else if acked_bytes > 0 {
        quic::advance_cycle(conn.bbr, round_done);
        quic::update_pacing_and_cwnd(conn.bbr);
    }
    conn.pacer = conn.bbr.pacer;
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

    let new_ecn_ce, _ = quic::validate_ecn(space, ack_frame, ecn_acked_pkts);

    quic::check_probe_rtt(conn.bbr, now_us, eff_rtt);
    let round_done = space.largest_acked_pn >= space.largest_sent_pn;
    update_bbr_on_ack(
        conn,
        in_flight_bytes,
        lost_bytes,
        acked_bytes,
        new_ecn_ce,
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

    return quic::ProcessResult { handled: true, needs_ack: false };
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

inline fn register_peer_reset_token(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) {
    guard frame.length >= 1 && frame.length <= 20 else { return; }
    let cid_len = frame.length as i64;
    guard frame.payload.len >= 17 else { return; }
    let tok_start = core::sub_sat_u64(frame.payload.len as u64, 16) as i64;
    guard tok_start == cid_len else { return; }
    let token_slice = frame.payload[tok_start..];
    for i in conn.peer_reset_tokens.len {
        if core::ct_eq_bytes(conn.peer_reset_tokens[i][..], token_slice) { return; }
    }
    if conn.peer_reset_tokens.len >= conn.peer_reset_tokens.cap {
        conn.peer_reset_tokens.remove_at(0);
    }
    var tok: u8[16] = [0; 16];
    for i in 16 { tok[i] = token_slice[i]; }
    conn.peer_reset_tokens.push(tok);
}

inline fn dispatch_conn_id_frame(conn: quic::QuicConnection&, frame: const quic::QuicFrame&) -> quic::ProcessResult {
    if frame.frame_type == quic::QuicFrameType.NewConnectionId {
        // RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
        if conn.dcid.len == 0 {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
        }
        register_peer_reset_token(conn, frame);
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    if frame.frame_type == quic::QuicFrameType.RetireConnectionId {
        // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
        if conn.scid.len == 0 {
            quic::close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return quic::ProcessResult { handled: false, needs_ack: false };
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

fn dispatch_crypto_inbound(
    conn:  quic::QuicConnection&,
    frame: const quic::QuicFrame&,
    htype: quic::QuicHeaderType,
) -> quic::ProcessResult {
    guard frame.payload.len > 0 else {
        return quic::ProcessResult { handled: true, needs_ack: true };
    }
    var ok = false;
    if htype == quic::QuicHeaderType.Initial {
        let _, ingested = tls::quic_crypto_stream_ingest(conn.initial_crypto, frame.offset, frame.payload);
        ok = ingested;
    } else if htype == quic::QuicHeaderType.Handshake {
        let _, ingested = tls::quic_crypto_stream_ingest(conn.handshake_crypto, frame.offset, frame.payload);
        ok = ingested;
    } else {
        let _, ingested = tls::quic_crypto_stream_ingest(conn.app_crypto, frame.offset, frame.payload);
        ok = ingested;
    }
    guard ok else {
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
        if ok {
            ack_f = decoded;
        }
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

// Derives QUIC Initial encryption keys and header protection keys for client and server
// from the initial Destination Connection ID (RFC 9001 §5.2, RFC 9369 §3.3).
fn quic_derive_initial_space_keys(
    dcid:     const u8[:],
    version:  u32,
    role:     quic::QuicRole,
    rx_space: quic::PnSpaceState&,
    tx_space: quic::PnSpaceState&,
) -> bool {
    let salt = rfc::quic_initial_salt(version);
    guard salt.len == 20 else { return false; }
    let prefix = rfc::quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }

    var initial_secret = core::hkdf_extract(salt, dcid);
    defer core::secure_zeroize_32(initial_secret);
    var client_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_secret);
    var server_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_secret);
    let sha256 = tls_internal::HASH_SHA256;
    let ok_c = tls_internal::hkdf_expand_label(
        sha256, initial_secret[..], "client in", [], 32, client_secret[..],
    );
    let ok_s = tls_internal::hkdf_expand_label(
        sha256, initial_secret[..], "server in", [], 32, server_secret[..],
    );
    guard ok_c && ok_s else { return false; }

    var lbl_key: u8[..16] = [];
    lbl_key.append(prefix);
    lbl_key.append("key");
    var lbl_iv: u8[..16] = [];
    lbl_iv.append(prefix);
    lbl_iv.append("iv");

    var c_key: u8[16] = [0; 16];
    defer core::secure_zeroize_16(c_key);
    var c_iv: u8[12] = [0; 12];
    var c_hp: u8[16] = [0; 16];
    defer core::secure_zeroize_16(c_hp);
    guard tls_internal::hkdf_expand_label(sha256, client_secret[..], lbl_key[..], [], 16, c_key[..])
        && tls_internal::hkdf_expand_label(sha256, client_secret[..], lbl_iv[..], [], 12, c_iv[..])
        && tls_internal::ks_derive_quic_hp_key(sha256, client_secret[..], 16, c_hp[..], version) else {
        return false;
    }

    var s_key: u8[16] = [0; 16];
    defer core::secure_zeroize_16(s_key);
    var s_iv: u8[12] = [0; 12];
    var s_hp: u8[16] = [0; 16];
    defer core::secure_zeroize_16(s_hp);
    guard tls_internal::hkdf_expand_label(sha256, server_secret[..], lbl_key[..], [], 16, s_key[..])
        && tls_internal::hkdf_expand_label(sha256, server_secret[..], lbl_iv[..], [], 12, s_iv[..])
        && tls_internal::ks_derive_quic_hp_key(sha256, server_secret[..], 16, s_hp[..], version) else {
        return false;
    }

    if role == quic::QuicRole.Client {
        return quic::install_keys(tx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
            && quic::install_keys(rx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
    }
    return quic::install_keys(rx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
        && quic::install_keys(tx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
}

fn quic_compute_hp_mask(space: const quic::PnSpaceState&, sample_slice: const u8[:]) -> u8[5], bool {
    guard sample_slice.len == 16 else { return [0; 5], false; }
    var sample: u8[16] = [0; 16];
    for i in 16 { sample[i] = sample_slice[i]; }

    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard space.hp_key.len == 16 else { return [0; 5], false; }
        var hp16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(hp16);
        for i in 16 { hp16[i] = space.hp_key[i]; }
        return aes128_header_protect_mask(hp16, sample), true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = space.hp_key[i]; }
        return aes256_header_protect_mask(hp32, sample), true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = space.hp_key[i]; }
        return chacha20_header_protect_mask(hp32, sample), true;
    }
    return [0; 5], false;
}

fn quic_aead_open_payload(
    space:      const quic::PnSpaceState&,
    pn:         u64,
    aad:        const u8[:],
    ciphertext: const u8[:],
    out_plain:  u8[..16384]&,
) -> bool {
    guard ciphertext.len >= 16 && space.aead_iv.len == 12 else { return false; }
    let pt_len = ciphertext.len - 16;
    guard pt_len <= out_plain.cap else { return false; }

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_nonce = tls::compute_record_nonce(iv12, pn);
    guard ok_nonce else { return false; }

    let is_aes128 = space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && space.aead_key.len == 16;
    let is_aes256 = space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && space.aead_key.len == 32;
    let is_chacha = space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && space.aead_key.len == 32;
    guard is_aes128 || is_aes256 || is_chacha else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ciphertext[pt_len + i]; }
    let ct_slice = ciphertext[..pt_len];

    out_plain.resize(pt_len, 0);
    if is_aes128 {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::fused_aes_gcm_decrypt(key16, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
        return true;
    }
    if is_aes256 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::aes256_gcm_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
        return true;
    }
    var key32: u8[32] = [0; 32];
    defer core::secure_zeroize_32(key32);
    for i in 32 { key32[i] = space.aead_key[i]; }
    let dec_len, ok_open = core::chacha20_poly1305_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
    guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
    return true;
}

fn quic_aead_seal_payload_inplace(
    space: const quic::PnSpaceState&,
    nonce: const u8[12]&,
    aad:   const u8[:],
    ct:    u8[:],
) -> u8[16], bool {
    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && space.aead_key.len == 16 {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = space.aead_key[i]; }
        return core::aes128_gcm_seal_inplace(key16, nonce, ct, aad);
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        return core::aes256_gcm_seal_inplace(key32, nonce, ct, aad);
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        return core::chacha20_poly1305_seal_inplace(key32, nonce, ct, aad);
    }
    return [0; 16], false;
}

// Computes the total wire length of a single QUIC packet within a coalesced datagram slice.
fn calc_coalesced_packet_wire_len(pkt_slice: const u8[:], hdr: const quic::QuicHeader&) -> i64, bool {
    if hdr.header_type == quic::QuicHeaderType.Initial
        || hdr.header_type == quic::QuicHeaderType.ZeroRtt
        || hdr.header_type == quic::QuicHeaderType.Handshake {
        let total_len = hdr.pn_offset + (hdr.payload_length as i64);
        guard total_len > 0 && total_len <= pkt_slice.len else { return 0, false; }
        return total_len, true;
    }
    return pkt_slice.len, true;
}

inline fn is_valid_inbound_dcid(conn: const quic::QuicConnection&, hdr: const quic::QuicHeader&) -> bool {
    if conn.role == quic::QuicRole.Server && hdr.header_type == quic::QuicHeaderType.Initial {
        if conn.packets_rx == 0 {
            // RFC 9000 Section 7.2: Negotiating Connection IDs - Accept >= 8-byte ODCID or server-chosen SCID.
            return hdr.dcid.len >= 8 || (conn.scid.len > 0 && core::ct_eq_bytes(hdr.dcid, conn.scid[..]));
        }
        if conn.original_dcid.len > 0 && core::ct_eq_bytes(hdr.dcid, conn.original_dcid[..]) {
            return true;
        }
    }
    if conn.scid.len == 0 {
        return hdr.dcid.len == 0;
    }
    return core::ct_eq_bytes(hdr.dcid, conn.scid[..]);
}

inline fn get_rx_space_keys_installed(conn: const quic::QuicConnection&, space_id: quic::PnSpaceId) -> bool {
    if space_id == quic::PnSpaceId.Initial { return conn.initial_space.keys_installed; }
    if space_id == quic::PnSpaceId.Handshake { return conn.handshake_space.keys_installed; }
    return conn.app_space.keys_installed;
}

inline fn is_pn_already_received(ranges: const quic::AckInterval[..64]&, pn: u64) -> bool {
    for i in ranges.len {
        let r = ranges[i];
        if pn > r.largest {
            return false;
        }
        if pn >= r.smallest {
            return true;
        }
    }
    return false;
}

// Decodes an unmasked packet number from an unencrypted test packet slice.
//
// Example:
//   pkt_slice = [0x40, 0x05], pn_offset = 1, pn_len = 1, space.largest_recv_pn = 4
//   returns: 5, ok = true
inline fn decode_unencrypted_test_pn(
    space:     const quic::PnSpaceState&,
    pkt_slice: const u8[:],
    pn_offset: u32,
    pn_len:    u8,
) -> u64, bool {
    let off:  i64 = pn_offset;
    let plen: i64 = pn_len;
    guard off >= 0 && plen >= 1 && plen <= 4 && core::add_sat_i64(off, plen) <= pkt_slice.len else {
        return 0, false;
    }
    var trunc_pn: u64 = 0;
    for i in plen {
        trunc_pn = core::shl_sat_u64(trunc_pn, 8) | pkt_slice[core::add_sat_i64(off, i)];
    }
    return quic::decode_packet_number_checked(space.largest_recv_pn, trunc_pn, pn_len);
}

// Removes RFC 9001 Header Protection and AEAD-decrypts an inbound QUIC packet when space keys are installed.
// Preserves `out_plaintext` with the unencrypted payload when `keys_installed` is false for unit test vectors.
// Returns `(fatal_err: u64, ok: bool)`, where `fatal_err != 0` indicates a fatal protocol violation.
fn verify_and_decrypt_packet(
    conn:          const quic::QuicConnection&,
    space_id:      quic::PnSpaceId,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    dgram_len:     i64,
    hdr:           quic::QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    let saved_hdr = hdr;
    var space .= conn.app_space;
    if space_id == quic::PnSpaceId.Initial {
        space .= conn.initial_space;
    } else if space_id == quic::PnSpaceId.Handshake {
        space .= conn.handshake_space;
    }
    let keys_installed = get_rx_space_keys_installed(conn, space_id);
    if !keys_installed {
        guard conn.allow_unencrypted_test_packets else { return 0, false; }
        // RFC 9000 Section 17.2.2: Initial Packet - Clients MUST reject Initial packets with non-zero Token Length.
        if conn.role == quic::QuicRole.Client && hdr.header_type == quic::QuicHeaderType.Initial && hdr.token.len > 0 {
            return rfc::QUIC_ERR_PROTOCOL_VIOLATION, false;
        }
        let pn_len = (pkt_slice[0] & 0x03) + 1;
        let test_pn, test_pn_ok = decode_unencrypted_test_pn(space, pkt_slice[..pkt_wire_len], hdr.pn_offset, pn_len);
        guard test_pn_ok && !is_pn_already_received(space.recv_ranges, test_pn) else { return 0, false; }
        hdr.packet_number = test_pn;
        hdr.pn_length = pn_len;
        hdr.header_len = hdr.pn_offset + pn_len;
        let raw_pl = get_packet_payload(pkt_slice[..pkt_wire_len], hdr);
        guard !(hdr.payload_length > hdr.pn_length && raw_pl.len == 0)
            && out_plaintext.try_set(raw_pl) else {
            hdr = saved_hdr;
            return 0, false;
        }
        return 0, true;
    }

    if hdr.header_type == quic::QuicHeaderType.Initial && conn.role == quic::QuicRole.Server {
        guard dgram_len >= 1200 else { return 0, false; }
    }
    guard is_valid_inbound_dcid(conn, hdr) else { return 0, false; }

    var work_pkt: u8[..16512] = [];
    guard pkt_wire_len > 0 && work_pkt.try_append(pkt_slice[..pkt_wire_len]) else { return 0, false; }

    let sample_slice, ok_samp = tls::quic_extract_hp_sample(work_pkt[..], hdr.pn_offset);
    guard ok_samp else { return 0, false; }
    let hp_mask, ok_mask = quic_compute_hp_mask(space, sample_slice);
    guard ok_mask else { return 0, false; }

    let pn_len, trunc_pn = quic::remove_header_protection(work_pkt[..], hdr.pn_offset, hp_mask);
    guard pn_len >= 1 && pn_len <= 4 else { return 0, false; }

    let unmasked_b0 = work_pkt[0];
    if (unmasked_b0 & 0x80) == 0 {
        hdr.key_phase = (unmasked_b0 & 0x04) != 0;
    }

    let full_pn, pn_ok = quic::decode_packet_number_checked(space.largest_recv_pn, trunc_pn, pn_len);
    // RFC 9000 Section 12.3: Packet Numbers - Discard duplicate packets before payload processing.
    guard pn_ok && !is_pn_already_received(space.recv_ranges, full_pn) else { return 0, false; }
    hdr.packet_number = full_pn;
    hdr.pn_length = pn_len;
    hdr.header_len = hdr.pn_offset + pn_len;
    let hdr_end = hdr.header_len as i64;
    guard hdr_end < work_pkt.len else { hdr = saved_hdr; return 0, false; }

    let aad = work_pkt[..hdr_end];
    let ciphertext = work_pkt[hdr_end..];
    guard quic_aead_open_payload(space, full_pn, aad, ciphertext, out_plaintext) else {
        hdr = saved_hdr;
        return 0, false;
    }

    // RFC 9000 Section 17.2.2: Initial Packet - Clients MUST reject Initial packets with non-zero Token Length.
    if conn.role == quic::QuicRole.Client && hdr.header_type == quic::QuicHeaderType.Initial && hdr.token.len > 0 {
        hdr = saved_hdr;
        out_plaintext.clear();
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION, false;
    }
    // RFC 9000 Section 17.2: Long Header Packets - Non-zero reserved bits after AEAD open are PROTOCOL_VIOLATION.
    // RFC 9000 Section 17.3.1: 1-RTT Packet - Non-zero reserved bits after AEAD open are PROTOCOL_VIOLATION.
    let reserved_mask: u8 = if (unmasked_b0 & 0x80) != 0 { 0x0C } else { 0x18 };
    guard (unmasked_b0 & reserved_mask) == 0 else {
        hdr = saved_hdr;
        out_plaintext.clear();
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION, false;
    }
    return 0, true;
}

// Verifies whether an incoming short-header datagram matches any registered peer
// Stateless Reset Token in constant time (RFC 9000 §10.3).
fn is_stateless_reset_datagram(conn: const quic::QuicConnection&, dgram: const u8[:]) -> bool {
    guard dgram.len >= 21 && (dgram[0] & 0x80) == 0 else { return false; }
    let tail_offset = core::sub_sat_u64(dgram.len as u64, 16) as i64;
    guard tail_offset >= 5 && tail_offset <= dgram.len else { return false; }
    let tail = dgram[tail_offset..];
    var matched = false;
    for i in conn.peer_reset_tokens.len {
        if core::ct_eq_bytes(tail, conn.peer_reset_tokens[i][..]) {
            matched = true;
        }
    }
    return matched;
}

// Reads a QUIC packet header before header protection removal by clearing masked reserved bits on byte 0
// when packet number space keys are installed (RFC 9001 §5.4, RFC 9287).
//
// Example:
//   pkt_slice = [0xC5, 0x00, 0x00, 0x00, 0x01, ...], dcid_len = 8 (initial keys installed)
//   returns: QuicHeader { header_type: Initial, version: 1, ... }, ok = true
fn parse_quic_packet_pre_hp(
    conn:      const quic::QuicConnection&,
    pkt_slice: const u8[:],
    dcid_len:  u8,
) -> quic::QuicHeader, bool {
    guard pkt_slice.len > 0 else { return quic::QuicHeader { .. }, false; }
    let raw_b0 = pkt_slice[0];
    if (raw_b0 & 0x80) != 0 {
        guard pkt_slice.len >= 5 else { return quic::QuicHeader { .. }, false; }
        let ver = core::read_be_u32(pkt_slice, 1);
        if ver == rfc::QUIC_VERSION_NEGOTIATION {
            return parse_quic_long_header(pkt_slice, raw_b0);
        }
        let opts = QuicHeaderOptions {
            allow_grease: conn.allow_grease_quic_bit,
            is_masked:    true,
        };
        return parse_quic_long_header(pkt_slice, raw_b0, opts);
    }
    let opts = QuicHeaderOptions {
        allow_grease: conn.allow_grease_quic_bit,
        is_masked:    true,
    };
    return parse_quic_short_header(pkt_slice, raw_b0, dcid_len, opts);
}

// Processes a single QUIC packet slice extracted from an inbound UDP datagram.
fn process_single_coalesced_packet(
    conn:      quic::QuicConnection&,
    pkt_slice: const u8[:],
    dgram_len: i64,
    now_us:    u64,
    out_ack:   quic::AckFrame&,
) -> i64, quic::ProcessResult {
    guard !quic_conn_is_closing_or_closed(conn.state) else {
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let dcid_len = conn.scid.len as u8;
    var hdr, ok = parse_quic_packet_pre_hp(conn, pkt_slice, dcid_len);
    guard ok else {
        if is_stateless_reset_datagram(conn, pkt_slice) {
            conn.state = quic::QuicConnState.Closed;
        }
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let pkt_wire_len, len_ok = calc_coalesced_packet_wire_len(pkt_slice, hdr);
    guard len_ok else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }

    if hdr.header_type == quic::QuicHeaderType.VersionNegotiation
        || hdr.header_type == quic::QuicHeaderType.Retry {
        let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
        guard res_pkt.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
        conn.packets_rx += 1;
        return pkt_wire_len, res_pkt;
    }

    let space_id = header_type_to_space_id(hdr.header_type);
    var plaintext_payload: u8[..16384] = [];
    let fatal_err, ok_dec = verify_and_decrypt_packet(
        conn, space_id, pkt_slice, pkt_wire_len, dgram_len, hdr, plaintext_payload,
    );
    guard ok_dec else {
        if fatal_err != 0 {
            quic::close(conn, fatal_err);
        } else if hdr.header_type == quic::QuicHeaderType.OneRtt && is_stateless_reset_datagram(conn, pkt_slice) {
            conn.state = quic::QuicConnState.Closed;
        }
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let res_frames = quic::process_payload(conn, plaintext_payload[..], hdr.header_type, now_us);
    guard res_frames.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }

    conn.packets_rx += 1;
    bind_initial_server_cids(conn, hdr);
    if quic_conn_is_closing_or_closed(conn.state) {
        return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: false };
    }
    let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard res_pkt.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
    return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: res_frames.needs_ack };
}
