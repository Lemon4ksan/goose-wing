// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic QUIC Connection Engine, Packet Number Spaces,
// Loss Recovery Coordinator, and Path Validation Reactor (RFC 9000, RFC 9002).
namespace internal;

import std;
import core from "..";
import .packet;
import .AckFrame;
import .bbr;
import .frames;
import .stream;
import .flow_control;
import .migration;
import .dplpmtud;
import tls.record;
import tls.key_schedule;

enum QuicRole {
    Client,
    Server,
}

enum QuicConnState {
    Initial,
    Handshake,
    Established,
    Closing,
    Closed,
}

struct QuicConnection {
    role:               QuicRole               = QuicRole.Server,
    state:              QuicConnState          = QuicConnState.Initial,
    scid:               u8[..20]               = [],
    dcid:               u8[..20]               = [],
    original_dcid:      u8[..20]               = [],
    initial_space:      PnSpaceState           = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    handshake_space:    PnSpaceState           = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    app_space:          PnSpaceState           = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    tx_initial_space:   PnSpaceState           = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    tx_handshake_space: PnSpaceState           = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    tx_app_space:       PnSpaceState           = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    initial_crypto:     wing::QuicCryptoStream = wing::QuicCryptoStream { .. },
    handshake_crypto:   wing::QuicCryptoStream = wing::QuicCryptoStream { .. },
    app_crypto:         wing::QuicCryptoStream = wing::QuicCryptoStream { .. },
    rtt:                RttState               = RttState { .. },
    pacer:              Pacer                  = Pacer { .. },
    bbr:                BbrState               = BbrState { .. },
    stream_table:       QuicStreamTable        = QuicStreamTable { .. },
    flow_ctrl:          QuicFlowControl        = QuicFlowControl { .. },
    bytes_received:     u64                    = 0,
    bytes_sent:         u64                    = 0,
    validated_address:  bool                   = false,
    packets_rx:         u64                    = 0,
    packets_tx:         u64                    = 0,
    close_code:         u64                    = 0,
    migration:          QuicMigrationManager   = QuicMigrationManager { .. },
    dplpmtud:           Dplpmtud               = Dplpmtud { .. },
}

fn new_quic_server_connection(scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role:              QuicRole.Server,
        state:             QuicConnState.Initial,
        bbr:               new_bbr_state(),
        stream_table:      new_quic_stream_table(QuicRole.Server),
        flow_ctrl:         new_quic_flow_control(65536, 65536),
        validated_address: false,
        ..
    };
    conn.pacer = conn.bbr.pacer;
    conn.scid.append(scid[..min(scid.len, conn.scid.cap)]);
    return conn;
}

fn new_quic_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role:              QuicRole.Client,
        state:             QuicConnState.Initial,
        bbr:               new_bbr_state(),
        stream_table:      new_quic_stream_table(QuicRole.Client),
        flow_ctrl:         new_quic_flow_control(65536, 65536),
        validated_address: true, // Client address validation is implicit
        ..
    };
    conn.pacer = conn.bbr.pacer;
    conn.dcid.append(server_dcid[..min(server_dcid.len, conn.dcid.cap)]);
    conn.scid.append(client_scid[..min(client_scid.len, conn.scid.cap)]);
    return conn;
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

// RFC 9000 §8.1: Server anti-amplification limit (3x bytes received) and path capacity
fn quic_conn_can_send(conn: const QuicConnection&, bytes: u64) -> bool {
    guard !conn.validated_address && conn.role == QuicRole.Server else {
        return path_can_send(conn.migration.active_path, bytes);
    }
    let limit = calc_amplification_limit(conn.bytes_received);
    return is_within_amplification_budget(conn.bytes_sent, bytes, limit);
}

// Advances the connection state machine
fn quic_conn_advance_state(conn: QuicConnection&, new_state: QuicConnState) {
    conn.state = new_state;
}

// Closes connection with RFC 9000 transport or application error code
fn quic_conn_close(conn: QuicConnection&, err_code: u64) {
    conn.close_code = err_code;
    conn.state = QuicConnState.Closing;
}

fn record_space_sent_packet(space: PnSpaceState&, meta: const SentPacketMeta&) {
    guard space.sent_packets.len < space.sent_packets.cap else { return; }
    space.has_sent_packets = true;
    if meta.pn > space.largest_sent_pn || space.sent_packets.len == 0 {
        space.largest_sent_pn = meta.pn;
    }
    if meta.ack_eliciting {
        space.time_of_last_ack_eliciting_us = meta.time_sent_us;
    }
    space.sent_packets.push(meta);
}

fn record_space_recv_packet(space: PnSpaceState&, pn: u64) {
    space.has_recv_packets = true;
    if pn > space.largest_recv_pn || space.recv_ranges.len == 0 {
        space.largest_recv_pn = pn;
    }
    record_received_pn(space.recv_ranges, pn);
}

fn generate_space_ack(space: PnSpaceState&, out_ack: AckFrame&) -> bool {
    guard space.recv_ranges.len > 0 else { return false; }
    let ack, ok = build_ack_frame(space.recv_ranges, 0);
    if ok {
        out_ack = ack;
        return true;
    }
    return false;
}

fn match_pn_in_ack_ranges(pn: u64, ranges: const AckInterval[..65]&) -> bool {
    for r_idx in ranges.len {
        if pn >= ranges[r_idx].smallest && pn <= ranges[r_idx].largest {
            return true;
        }
    }
    return false;
}

// Marks packets matching `ranges` as acknowledged, removing them from `sent_packets`
// and returning `(acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts)`.
fn mark_acked_packets_in_space(
    space:  PnSpaceState&,
    ranges: const AckInterval[..65]&,
    now_us: u64,
) -> u64, u64, u64, u64 {
    var acked_bytes:     u64 = 0;
    var latest_rtt_us:   u64 = 0;
    var in_flight_bytes: u64 = 0;
    var new_acked_pkts:  u64 = 0;

    if !space.has_acked_packets || ranges[0].largest > space.largest_acked_pn {
        space.largest_acked_pn = ranges[0].largest;
        space.has_acked_packets = true;
    }

    var i: i64 = 0;
    while i < space.sent_packets.len {
        let pkt = space.sent_packets[i];
        if match_pn_in_ack_ranges(pkt.pn, ranges) {
            new_acked_pkts += 1;
            if pkt.in_flight {
                acked_bytes += pkt.size_bytes;
            }
            if pkt.pn == ranges[0].largest && pkt.ack_eliciting {
                latest_rtt_us = if now_us >= pkt.time_sent_us { now_us - pkt.time_sent_us } else { 0 };
            }
            space.sent_packets.remove_at(i);
        } else {
            if pkt.in_flight {
                in_flight_bytes += pkt.size_bytes;
            }
            i += 1;
        }
    }
    return acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts;
}

fn calc_lost_bytes(lost_pkts: const SentPacketMeta[..128]&) -> u64 {
    var lost_bytes: u64 = 0;
    for i in lost_pkts.len {
        if lost_pkts[i].in_flight {
            lost_bytes += lost_pkts[i].size_bytes;
        }
    }
    return lost_bytes;
}

inline fn update_bbr_sample_bw(bbr: BbrState&, acked_bytes: u64, eff_rtt: u64) {
    if acked_bytes > 0 && eff_rtt > 0 {
        let sample_bw = (acked_bytes * 8000000) / eff_rtt;
        if sample_bw > bbr.bw_hi_bps {
            bbr.bw_hi_bps = sample_bw;
        }
    }
}

inline fn update_bbr_on_ack(
    conn:            QuicConnection&,
    in_flight_bytes: u64,
    lost_bytes:      u64,
    acked_bytes:     u64,
    ecn_ce_count:    u64,
    new_acked_pkts:  u64,
    round_done:      bool,
) {
    if lost_bytes > 0 || ecn_ce_count > 0 {
        bbr_update_pacing_and_cwnd(conn.bbr);
        bbr_on_congestion_signal(
            conn.bbr,
            in_flight_bytes,
            lost_bytes,
            acked_bytes,
            ecn_ce_count,
            new_acked_pkts,
        );
    } else if acked_bytes > 0 {
        bbr_advance_cycle(conn.bbr, round_done);
        bbr_update_pacing_and_cwnd(conn.bbr);
    }
    conn.pacer = conn.bbr.pacer;
}

// Processes a validated ACK frame in `space`, updating RTT, loss detection, and BBRv3 congestion control.
fn process_space_ack(
    conn:      QuicConnection&,
    space:     PnSpaceState&,
    ack_frame: const AckFrame&,
    now_us:    u64,
    is_app:    bool,
) -> bool {
    var acked_ranges: AckInterval[..65] = [];
    let ok = parse_and_validate_ack(space, ack_frame, acked_ranges);
    guard ok else {
        quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return false;
    }

    let acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts =
        mark_acked_packets_in_space(space, acked_ranges, now_us);

    if new_acked_pkts > 0 && latest_rtt_us > 0 {
        let ack_delay_us = ack_frame.ack_delay << 3;
        update_rtt(conn.rtt, latest_rtt_us, ack_delay_us, is_app && conn.state == QuicConnState.Established, now_us);
    }

    let eff_rtt = if latest_rtt_us > 0 { latest_rtt_us } else { conn.rtt.smoothed_rtt_us };
    update_bbr_sample_bw(conn.bbr, acked_bytes, eff_rtt);

    var lost_pkts: SentPacketMeta[..128] = [];
    let _ = detect_lost_packets(space, conn.rtt, now_us, lost_pkts);
    let lost_bytes = calc_lost_bytes(lost_pkts);

    var new_ecn_ce: u64 = 0;
    if ack_frame.is_ecn && ack_frame.ecn_ce_count > space.largest_acked_ce {
        new_ecn_ce = ack_frame.ecn_ce_count - space.largest_acked_ce;
        space.largest_acked_ce = ack_frame.ecn_ce_count;
    }

    bbr_check_probe_rtt(conn.bbr, now_us, eff_rtt);
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

// Routes an inbound ACK frame to loss recovery, RTT estimation, and the BBRv3 state machine.
fn quic_conn_on_ack(
    conn:      QuicConnection&,
    ack_frame: const AckFrame&,
    now_us:    u64       = 100000,
    space_id:  PnSpaceId = PnSpaceId.ApplicationData,
) -> bool {
    if space_id == PnSpaceId.Initial {
        return process_space_ack(conn, conn.initial_space, ack_frame, now_us, false);
    }
    if space_id == PnSpaceId.Handshake {
        return process_space_ack(conn, conn.handshake_space, ack_frame, now_us, false);
    }
    return process_space_ack(conn, conn.app_space, ack_frame, now_us, true);
}

// Records an egress packet for loss recovery and anti-amplification tracking
fn quic_conn_record_sent(
    conn:          QuicConnection&,
    space_id:      PnSpaceId,
    pn:            u64,
    size_bytes:    u64,
    ack_eliciting: bool,
    now_us:        u64,
) {
    conn.bytes_sent = core::add_sat_u64(conn.bytes_sent, size_bytes);
    conn.packets_tx = conn.packets_tx + 1;

    let meta = SentPacketMeta {
        pn:            pn,
        time_sent_us:  now_us,
        size_bytes:    size_bytes,
        ack_eliciting: ack_eliciting,
        in_flight:     ack_eliciting,
    };

    match space_id {
        Initial => record_space_sent_packet(conn.initial_space, meta),
        Handshake => record_space_sent_packet(conn.handshake_space, meta),
        ApplicationData => record_space_sent_packet(conn.app_space, meta),
    }
}

fn bind_initial_server_cids(conn: QuicConnection&, hdr: const QuicHeader&) {
    guard conn.role == QuicRole.Server && conn.packets_rx == 1 else { return; }
    if conn.dcid.len == 0 {
        conn.dcid.append(hdr.scid[..]);
    }
    if conn.original_dcid.len == 0 {
        conn.original_dcid.append(hdr.dcid[..]);
    }
}

fn dispatch_packet_type(conn: QuicConnection&, hdr: const QuicHeader&, out_ack: AckFrame&) -> bool, bool {
    guard conn.state != QuicConnState.Closing && conn.state != QuicConnState.Closed else {
        return false, false;
    }

    if hdr.header_type == QuicHeaderType.Initial {
        record_space_recv_packet(conn.initial_space, hdr.packet_number);
        let needs_ack = generate_space_ack(conn.initial_space, out_ack);
        return true, needs_ack;
    }

    if hdr.header_type == QuicHeaderType.Handshake {
        if conn.state == QuicConnState.Initial {
            conn.state = QuicConnState.Handshake;
        }
        if conn.role == QuicRole.Server {
            conn.validated_address = true;
        }
        record_space_recv_packet(conn.handshake_space, hdr.packet_number);
        let needs_ack = generate_space_ack(conn.handshake_space, out_ack);
        return true, needs_ack;
    }

    if hdr.header_type == QuicHeaderType.OneRtt {
        if conn.state == QuicConnState.Handshake || conn.state == QuicConnState.Initial {
            conn.state = QuicConnState.Established;
            conn.validated_address = true;
        }
        record_space_recv_packet(conn.app_space, hdr.packet_number);
        let needs_ack = generate_space_ack(conn.app_space, out_ack);
        return true, needs_ack;
    }

    return true, false;
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

fn get_packet_payload(dgram: const u8[:], hdr: const QuicHeader&) -> u8[:] {
    let start: i64 = hdr.header_len;
    guard start <= dgram.len else { return dgram[..0]; }
    if hdr.header_type != QuicHeaderType.OneRtt {
        return get_bounded_payload(dgram, start, hdr.payload_length, hdr.pn_length);
    }
    return dgram[start..];
}

inline fn validate_stream_recv_final_size(
    s:          const QuicStream&,
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

fn dispatch_stream_inbound(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 Section 19.8: STREAM Frames - Ingress STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return false, false;
    }

    let end_offset = frame.offset + frame.length;
    guard validate_stream_recv_final_size(conn.stream_table.streams[idx], end_offset, frame.fin) else {
        quic_conn_close(conn, rfc::QUIC_ERR_FINAL_SIZE);
        return false, false;
    }

    let fc_ok, fc_err = quic_fc_record_recv_stream(
        conn.flow_ctrl,
        conn.stream_table.streams[idx],
        frame.offset,
        frame.length,
    );
    guard fc_ok else {
        quic_conn_close(conn, fc_err);
        return false, false;
    }

    let st_ok, st_err = quic_stream_on_recv_stream_frame(
        conn.stream_table.streams[idx],
        frame.offset,
        frame.length,
        frame.fin,
    );
    guard st_ok else {
        quic_conn_close(conn, st_err);
        return false, false;
    }

    return true, true;
}

fn dispatch_reset_stream_inbound(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 §19.4: Ingress RESET_STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return false, false;
    }

    let fc_ok, fc_err = quic_fc_record_recv_reset(conn.flow_ctrl, conn.stream_table.streams[idx], frame.final_size);
    guard fc_ok else {
        quic_conn_close(conn, fc_err);
        return false, false;
    }

    let st_ok, st_err = quic_stream_on_recv_reset(conn.stream_table.streams[idx], frame.error_code, frame.final_size);
    guard st_ok else {
        quic_conn_close(conn, st_err);
        return false, false;
    }

    return true, true;
}

fn dispatch_stop_sending_inbound(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    guard quic_stream_can_send(frame.stream_id, conn.role) else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 §19.5: Ingress STOP_SENDING frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, rfc::QUIC_ERR_STREAM_LIMIT);
        return false, false;
    }

    let st_ok, st_err = quic_stream_on_recv_stop_sending(conn.stream_table.streams[idx], frame.error_code, conn.role);
    guard st_ok else {
        quic_conn_close(conn, st_err);
        return false, false;
    }

    return true, true;
}

fn dispatch_flow_control_inbound(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    if frame.frame_type == QuicFrameType.MaxData {
        quic_fc_update_remote_max_data(conn.flow_ctrl, frame.max_data);
        return true, true;
    }

    if frame.frame_type == QuicFrameType.MaxStreamData {
        guard quic_stream_can_send(frame.stream_id, conn.role) else {
            quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return false, false;
        }
        // RFC 9000 §19.10: Ingress MAX_STREAM_DATA frame for unopened locally-initiated stream is STREAM_STATE_ERROR
        if !is_peer_initiated_stream(frame.stream_id, conn.role) {
            let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
            guard sid_found >= 0 else {
                quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
                return false, false;
            }
        }
        let idx = quic_table_find_stream(conn.stream_table, frame.stream_id);
        if idx >= 0 {
            quic_fc_update_stream_send_max_data(conn.stream_table.streams[idx], frame.max_data);
        }
        return true, true;
    }

    if frame.frame_type == QuicFrameType.MaxStreamsBidi {
        if frame.max_data > conn.stream_table.max_streams_bidi {
            conn.stream_table.max_streams_bidi = frame.max_data;
        }
        return true, true;
    }

    if frame.frame_type == QuicFrameType.MaxStreamsUni {
        if frame.max_data > conn.stream_table.max_streams_uni {
            conn.stream_table.max_streams_uni = frame.max_data;
        }
        return true, true;
    }

    if frame.frame_type == QuicFrameType.StreamDataBlocked {
        // RFC 9000 §19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only
        // stream MUST terminate the connection with error STREAM_STATE_ERROR."
        guard quic_stream_can_recv(frame.stream_id, conn.role) else {
            quic_conn_close(conn, rfc::QUIC_ERR_STREAM_STATE);
            return false, false;
        }
        return true, true;
    }

    return true, true;
}

inline fn dispatch_conn_id_frame(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    if frame.frame_type == QuicFrameType.NewConnectionId {
        // RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
        if conn.dcid.len == 0 {
            quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        return true, true;
    }
    if frame.frame_type == QuicFrameType.RetireConnectionId {
        // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
        if conn.scid.len == 0 {
            quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        return true, true;
    }
    return true, true;
}

fn dispatch_session_frame(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    if frame.frame_type == QuicFrameType.ConnectionClose || frame.frame_type == QuicFrameType.ConnectionCloseApp {
        quic_conn_close(conn, frame.error_code);
        return true, false;
    }
    if frame.frame_type == QuicFrameType.HandshakeDone {
        if conn.role == QuicRole.Server {
            quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        if conn.state != QuicConnState.Closing && conn.state != QuicConnState.Closed {
            conn.state = QuicConnState.Established;
        }
        return true, true;
    }
    if frame.frame_type == QuicFrameType.NewToken {
        // RFC 9000 §19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt
        // of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
        if conn.role == QuicRole.Server {
            quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        return true, true;
    }
    if frame.frame_type == QuicFrameType.PathChallenge {
        return true, true;
    }
    if frame.frame_type == QuicFrameType.PathResponse {
        let ok = quic_migration_on_path_response(conn.migration, frame.payload);
        if ok {
            quic_migration_complete(conn.migration);
            conn.validated_address = true;
        }
        return true, true;
    }
    if frame.frame_type == QuicFrameType.NewConnectionId || frame.frame_type == QuicFrameType.RetireConnectionId {
        return dispatch_conn_id_frame(conn, frame);
    }
    if frame.frame_type == QuicFrameType.DataBlocked
        || frame.frame_type == QuicFrameType.StreamsBlockedBidi
        || frame.frame_type == QuicFrameType.StreamsBlockedUni
        || frame.frame_type == QuicFrameType.Datagram {
        return true, true;
    }
    quic_conn_close(conn, rfc::QUIC_ERR_FRAME_ENCODING);
    return false, false;
}

fn dispatch_crypto_inbound(conn: QuicConnection&, frame: const QuicFrame&, htype: QuicHeaderType) -> bool, bool {
    guard frame.payload.len > 0 else {
        return true, true;
    }
    var ok = false;
    if htype == QuicHeaderType.Initial {
        let ingested, _ = wing::quic_crypto_stream_ingest(conn.initial_crypto, frame.offset, frame.payload);
        ok = ingested;
    } else if htype == QuicHeaderType.Handshake {
        let ingested, _ = wing::quic_crypto_stream_ingest(conn.handshake_crypto, frame.offset, frame.payload);
        ok = ingested;
    } else {
        let ingested, _ = wing::quic_crypto_stream_ingest(conn.app_crypto, frame.offset, frame.payload);
        ok = ingested;
    }
    guard ok else {
        quic_conn_close(conn, rfc::QUIC_ERR_CRYPTO_BUFFER_EXCEEDED);
        return false, false;
    }
    return true, true;
}

fn dispatch_inbound_frame(
    conn:  QuicConnection&,
    frame: const QuicFrame&,
    htype: QuicHeaderType = QuicHeaderType.OneRtt,
) -> bool, bool {
    if frame.frame_type == QuicFrameType.Padding {
        return true, false;
    }
    if frame.frame_type == QuicFrameType.Ping {
        return true, true;
    }
    if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
        return true, false;
    }
    if frame.frame_type == QuicFrameType.Crypto {
        return dispatch_crypto_inbound(conn, frame, htype);
    }
    if frame.frame_type == QuicFrameType.Stream {
        return dispatch_stream_inbound(conn, frame);
    }
    if frame.frame_type == QuicFrameType.ResetStream {
        return dispatch_reset_stream_inbound(conn, frame);
    }
    if frame.frame_type == QuicFrameType.StopSending {
        return dispatch_stop_sending_inbound(conn, frame);
    }
    if frame.frame_type == QuicFrameType.MaxData
        || frame.frame_type == QuicFrameType.MaxStreamData
        || frame.frame_type == QuicFrameType.StreamDataBlocked
        || frame.frame_type == QuicFrameType.MaxStreamsBidi
        || frame.frame_type == QuicFrameType.MaxStreamsUni {
        return dispatch_flow_control_inbound(conn, frame);
    }
    return dispatch_session_frame(conn, frame);
}

// RFC 9000 Section 9.1: Initiates connection migration toward new remote endpoint
fn quic_conn_migrate(conn: QuicConnection&, new_addr: const QuicEndpointAddr&, token: const u8[8]&) {
    quic_migration_start_probing(conn.migration, new_addr, token);
}

// RFC 8899 Section 5.1: Handles acknowledgement of DPLPMTUD probe packet
fn quic_conn_on_probe_acked(conn: QuicConnection&, acked_size: u32) -> bool {
    return dplpmtud_on_probe_acked(conn.dplpmtud, acked_size);
}

// RFC 8899 Section 5.1: Handles loss / timeout of DPLPMTUD probe packet
fn quic_conn_on_probe_lost(conn: QuicConnection&, lost_size: u32) -> bool {
    return dplpmtud_on_probe_lost(conn.dplpmtud, lost_size);
}

// RFC 9000 Section 12.5 (Table 3): Validates whether a frame type is permitted in a packet type.
inline fn quic_is_frame_allowed_in_packet(ftype: QuicFrameType, htype: QuicHeaderType) -> bool {
    guard ftype != QuicFrameType.Unknown else { return false; }
    guard htype != QuicHeaderType.Retry && htype != QuicHeaderType.VersionNegotiation else {
        return false;
    }
    if htype == QuicHeaderType.Initial || htype == QuicHeaderType.Handshake {
        return ftype == QuicFrameType.Padding
            || ftype == QuicFrameType.Ping
            || ftype == QuicFrameType.Ack
            || ftype == QuicFrameType.AckEcn
            || ftype == QuicFrameType.Crypto
            || ftype == QuicFrameType.ConnectionClose;
    }
    if htype == QuicHeaderType.ZeroRtt {
        if ftype == QuicFrameType.Ack
            || ftype == QuicFrameType.AckEcn
            || ftype == QuicFrameType.Crypto
            || ftype == QuicFrameType.HandshakeDone
            || ftype == QuicFrameType.NewToken
            || ftype == QuicFrameType.PathChallenge
            || ftype == QuicFrameType.PathResponse
            || ftype == QuicFrameType.RetireConnectionId
            || ftype == QuicFrameType.ConnectionClose
            || ftype == QuicFrameType.ConnectionCloseApp {
            return false;
        }
        return true;
    }
    return true;
}

inline fn header_type_to_space_id(htype: QuicHeaderType) -> PnSpaceId {
    if htype == QuicHeaderType.Initial {
        return PnSpaceId.Initial;
    }
    if htype == QuicHeaderType.Handshake {
        return PnSpaceId.Handshake;
    }
    return PnSpaceId.ApplicationData;
}

fn dispatch_inbound_ack_frame(
    conn:   QuicConnection&,
    frame:  const QuicFrame&,
    htype:  QuicHeaderType,
    now_us: u64,
) -> bool {
    var ack_f = AckFrame {
        is_ecn:          frame.frame_type == QuicFrameType.AckEcn,
        largest_acked:   frame.offset,
        ack_delay:       frame.max_data,
        first_ack_range: frame.length,
        ..
    };
    if frame.payload.len > 0 {
        let decoded, _, ok = decode_ack_frame(frame.payload, 0);
        if ok {
            ack_f = decoded;
        }
    }
    let space_id = header_type_to_space_id(htype);
    var has_sent = conn.app_space.has_sent_packets;
    if space_id == PnSpaceId.Initial {
        has_sent = conn.initial_space.has_sent_packets;
    } else if space_id == PnSpaceId.Handshake {
        has_sent = conn.handshake_space.has_sent_packets;
    }
    guard has_sent else {
        quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return false;
    }
    return quic_conn_on_ack(conn, ack_f, now_us, space_id);
}

fn quic_conn_process_payload(
    conn:    QuicConnection&,
    payload: const u8[:],
    htype:   QuicHeaderType = QuicHeaderType.OneRtt,
    now_us:  u64            = 100000,
) -> bool, bool {
    guard conn.state != QuicConnState.Closing && conn.state != QuicConnState.Closed else {
        return false, false;
    }
    // RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
    guard payload.len > 0 else {
        quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return false, false;
    }
    var idx: i64 = 0;
    var any_ack_el = false;

    while idx < payload.len {
        let frame, ok = decode_quic_frame_cursor(payload, idx);
        guard ok else {
            quic_conn_close(conn, rfc::QUIC_ERR_FRAME_ENCODING);
            return false, false;
        }

        guard quic_is_frame_allowed_in_packet(frame.frame_type, htype) else {
            quic_conn_close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }

        if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
            guard dispatch_inbound_ack_frame(conn, frame, htype, now_us) else {
                return false, false;
            }
        }

        let handled, ack_el = dispatch_inbound_frame(conn, frame, htype);
        guard handled else { return false, false; }
        if ack_el {
            any_ack_el = true;
        }
    }

    return true, any_ack_el;
}

// Derives QUIC Initial encryption keys and header protection keys for client and server
// from the initial Destination Connection ID (RFC 9001 §5.2, RFC 9369 §3.3).
fn quic_derive_initial_space_keys(
    dcid:     const u8[:],
    version:  u32,
    role:     QuicRole,
    rx_space: PnSpaceState&,
    tx_space: PnSpaceState&,
) -> bool {
    let salt = quic_initial_salt(version);
    guard salt.len == 20 else { return false; }
    let prefix = quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }

    var initial_secret = core::hkdf_extract(salt, dcid);
    var client_secret: u8[32] = [0; 32];
    var server_secret: u8[32] = [0; 32];
    let ok_c = hkdf_expand_label(HASH_SHA256, initial_secret[..], "client in", [], 32, client_secret[..]);
    let ok_s = hkdf_expand_label(HASH_SHA256, initial_secret[..], "server in", [], 32, server_secret[..]);
    core::secure_zeroize_32(initial_secret);
    guard ok_c && ok_s else {
        core::secure_zeroize_32(client_secret);
        core::secure_zeroize_32(server_secret);
        return false;
    }

    var lbl_key: u8[..16] = [];
    lbl_key.append(prefix);
    lbl_key.append("key");
    var lbl_iv: u8[..16] = [];
    lbl_iv.append(prefix);
    lbl_iv.append("iv");

    var c_key: u8[16] = [0; 16];
    var c_iv:  u8[12] = [0; 12];
    var c_hp:  u8[16] = [0; 16];
    guard hkdf_expand_label(HASH_SHA256, client_secret[..], lbl_key[..], [], 16, c_key[..])
        && hkdf_expand_label(HASH_SHA256, client_secret[..], lbl_iv[..], [], 12, c_iv[..])
        && ks_derive_quic_hp_key(HASH_SHA256, client_secret[..], 16, c_hp[..], version) else {
        core::secure_zeroize_16(c_key);
        core::secure_zeroize_16(c_hp);
        core::secure_zeroize_32(client_secret);
        core::secure_zeroize_32(server_secret);
        return false;
    }

    var s_key: u8[16] = [0; 16];
    var s_iv:  u8[12] = [0; 12];
    var s_hp:  u8[16] = [0; 16];
    guard hkdf_expand_label(HASH_SHA256, server_secret[..], lbl_key[..], [], 16, s_key[..])
        && hkdf_expand_label(HASH_SHA256, server_secret[..], lbl_iv[..], [], 12, s_iv[..])
        && ks_derive_quic_hp_key(HASH_SHA256, server_secret[..], 16, s_hp[..], version) else {
        core::secure_zeroize_16(c_key);
        core::secure_zeroize_16(c_hp);
        core::secure_zeroize_16(s_key);
        core::secure_zeroize_16(s_hp);
        core::secure_zeroize_32(client_secret);
        core::secure_zeroize_32(server_secret);
        return false;
    }

    core::secure_zeroize_32(client_secret);
    core::secure_zeroize_32(server_secret);

    var ok_install = false;
    if role == QuicRole.Client {
        ok_install = quic_install_pn_space_keys(tx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
            && quic_install_pn_space_keys(rx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
    } else {
        ok_install = quic_install_pn_space_keys(rx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
            && quic_install_pn_space_keys(tx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
    }
    core::secure_zeroize_16(c_key);
    core::secure_zeroize_16(c_hp);
    core::secure_zeroize_16(s_key);
    core::secure_zeroize_16(s_hp);
    return ok_install;
}

fn quic_conn_install_initial_keys(
    conn:    QuicConnection&,
    dcid:    const u8[:],
    version: u32 = rfc::QUIC_VERSION_1,
) -> bool {
    return quic_derive_initial_space_keys(dcid, version, conn.role, conn.initial_space, conn.tx_initial_space);
}

fn quic_compute_hp_mask(space: const PnSpaceState&, sample_slice: const u8[:]) -> u8[5], bool {
    guard sample_slice.len == 16 else { return [0; 5], false; }
    var sample: u8[16] = [0; 16];
    for i in 16 { sample[i] = sample_slice[i]; }

    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard space.hp_key.len == 16 else { return [0; 5], false; }
        var hp16: u8[16] = [0; 16];
        for i in 16 { hp16[i] = space.hp_key[i]; }
        let mask = aes128_header_protect_mask(hp16, sample);
        core::secure_zeroize_16(hp16);
        return mask, true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        for i in 32 { hp32[i] = space.hp_key[i]; }
        let mask = aes256_header_protect_mask(hp32, sample);
        core::secure_zeroize_32(hp32);
        return mask, true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        for i in 32 { hp32[i] = space.hp_key[i]; }
        let mask = chacha20_header_protect_mask(hp32, sample);
        core::secure_zeroize_32(hp32);
        return mask, true;
    }
    return [0; 5], false;
}

fn quic_aead_open_payload(
    space:      const PnSpaceState&,
    pn:         u64,
    aad:        const u8[:],
    ciphertext: const u8[:],
    out_plain:  u8[..16384]&,
) -> bool {
    out_plain.clear();
    guard ciphertext.len >= 16 && space.aead_iv.len == 12 else { return false; }
    let pt_len = ciphertext.len - 16;
    guard pt_len <= out_plain.cap else { return false; }

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_nonce = wing::compute_record_nonce(iv12, pn);
    guard ok_nonce else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ciphertext[pt_len + i]; }
    let ct_slice = ciphertext[..pt_len];

    out_plain.resize(pt_len, 0);
    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard space.aead_key.len == 16 else { out_plain.clear(); return false; }
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::fused_aes_gcm_decrypt(key16, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        core::secure_zeroize_16(key16);
        guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
        return true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard space.aead_key.len == 32 else { out_plain.clear(); return false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::aes256_gcm_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        core::secure_zeroize_32(key32);
        guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
        return true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard space.aead_key.len == 32 else { out_plain.clear(); return false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::chacha20_poly1305_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        core::secure_zeroize_32(key32);
        guard ok_open && dec_len == pt_len else { out_plain.clear(); return false; }
        return true;
    }
    out_plain.clear();
    return false;
}

fn quic_aead_seal_payload_inplace(
    space: const PnSpaceState&,
    nonce: const u8[12]&,
    aad:   const u8[:],
    ct:    u8[:],
) -> u8[16], bool {
    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && space.aead_key.len == 16 {
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = space.aead_key[i]; }
        let tag, ok = core::aes128_gcm_seal_inplace(key16, nonce, ct, aad);
        core::secure_zeroize_16(key16);
        return tag, ok;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = space.aead_key[i]; }
        let tag, ok = core::aes256_gcm_seal_inplace(key32, nonce, ct, aad);
        core::secure_zeroize_32(key32);
        return tag, ok;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = space.aead_key[i]; }
        let tag, ok = core::chacha20_poly1305_seal_inplace(key32, nonce, ct, aad);
        core::secure_zeroize_32(key32);
        return tag, ok;
    }
    return [0; 16], false;
}

// Seals and applies RFC 9001 Header Protection to a QUIC packet payload in `space`.
fn quic_seal_packet<B>(
    space:     const PnSpaceState&,
    hdr:       const QuicHeader&,
    pn_len:    u8,
    plaintext: const u8[:],
    out_pkt:   B&,
) -> bool {
    guard space.keys_installed && space.aead_iv.len == 12 else { return false; }
    guard pn_len >= 1 && pn_len <= 4 && plaintext.len > 0 else { return false; }

    var hdr_wire = hdr;
    if hdr_wire.header_type != QuicHeaderType.OneRtt {
        hdr_wire.payload_length = (pn_len as u64) + (plaintext.len as u64) + 16;
    }

    var work_hdr: u8[..600] = [];
    guard encode_quic_header(work_hdr, hdr_wire, pn_len) else { return false; }
    let pn_offset = (work_hdr.len - (pn_len as i64)) as u32;

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_nonce = wing::compute_record_nonce(iv12, hdr.packet_number);
    guard ok_nonce else { return false; }

    var ct_buf: u8[..16384] = [];
    guard ct_buf.try_append(plaintext) else { return false; }
    let tag, ok_seal = quic_aead_seal_payload_inplace(space, nonce, work_hdr[..], ct_buf[..]);
    guard ok_seal else { return false; }

    var full_pkt: u8[..17000] = [];
    guard full_pkt.try_append(work_hdr[..])
        && full_pkt.try_append(ct_buf[..])
        && full_pkt.try_append(tag[..]) else {
        return false;
    }

    let sample_slice, ok_samp = wing::quic_extract_hp_sample(full_pkt[..], pn_offset);
    guard ok_samp else { return false; }
    let hp_mask, ok_mask = quic_compute_hp_mask(space, sample_slice);
    guard ok_mask else { return false; }

    apply_header_protection(full_pkt[..], pn_offset, pn_len, hp_mask);
    return out_pkt.try_append(full_pkt[..]);
}

// Computes the total wire length of a single QUIC packet within a coalesced datagram slice.
// Long Header packets with explicit Length (`Initial`, `ZeroRtt`, `Handshake`) end at
// `header_len + (payload_length - pn_length)`; Short Header (`OneRtt`) consumes the remainder.
fn calc_coalesced_packet_wire_len(pkt_slice: const u8[:], hdr: const QuicHeader&) -> i64, bool {
    let start: i64 = hdr.header_len;
    guard start <= pkt_slice.len else { return 0, false; }
    if hdr.header_type == QuicHeaderType.Initial
        || hdr.header_type == QuicHeaderType.ZeroRtt
        || hdr.header_type == QuicHeaderType.Handshake {
        guard hdr.payload_length >= hdr.pn_length else { return 0, false; }
        let blen = (hdr.payload_length - hdr.pn_length) as i64;
        guard blen > 0 else { return 0, false; }
        let total_len = start + blen;
        guard total_len <= pkt_slice.len else { return 0, false; }
        return total_len, true;
    }
    return pkt_slice.len, true;
}

inline fn get_rx_space_keys_installed(conn: const QuicConnection&, space_id: PnSpaceId) -> bool {
    if space_id == PnSpaceId.Initial { return conn.initial_space.keys_installed; }
    if space_id == PnSpaceId.Handshake { return conn.handshake_space.keys_installed; }
    return conn.app_space.keys_installed;
}

// Removes RFC 9001 Header Protection and AEAD-decrypts an inbound QUIC packet when space keys are installed.
// Preserves `out_plaintext` with the unencrypted payload when `keys_installed` is false for unit test vectors.
fn verify_and_decrypt_packet(
    conn:          const QuicConnection&,
    space_id:      PnSpaceId,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    hdr:           QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> bool {
    out_plaintext.clear();
    let keys_installed = get_rx_space_keys_installed(conn, space_id);
    if !keys_installed {
        let raw_pl = get_packet_payload(pkt_slice[..pkt_wire_len], hdr);
        if hdr.payload_length > hdr.pn_length && raw_pl.len == 0 {
            return false;
        }
        return out_plaintext.try_append(raw_pl);
    }

    if hdr.header_type == QuicHeaderType.Initial && conn.role == QuicRole.Server {
        guard pkt_slice.len >= 1200 else { return false; }
    }
    if conn.scid.len > 0 {
        guard core::ct_eq_bytes(hdr.dcid, conn.scid[..]) else { return false; }
    }

    let space = if space_id == PnSpaceId.Initial {
        conn.initial_space
    } else if space_id == PnSpaceId.Handshake {
        conn.handshake_space
    } else {
        conn.app_space
    };

    var work_pkt: u8[..16512] = [];
    guard pkt_wire_len > 0 && pkt_wire_len <= work_pkt.cap else { return false; }
    work_pkt.append(pkt_slice[..pkt_wire_len]);

    let sample_slice, ok_samp = wing::quic_extract_hp_sample(work_pkt[..], hdr.pn_offset);
    guard ok_samp else { return false; }
    let hp_mask, ok_mask = quic_compute_hp_mask(space, sample_slice);
    guard ok_mask else { return false; }

    let pn_len, trunc_pn = remove_header_protection(work_pkt[..], hdr.pn_offset, hp_mask);
    guard pn_len >= 1 && pn_len <= 4 else { return false; }

    let unmasked_b0 = work_pkt[0];
    if (unmasked_b0 & 0x80) != 0 {
        guard (unmasked_b0 & 0x0C) == 0 else { return false; }
    } else {
        guard (unmasked_b0 & 0x18) == 0 else { return false; }
        hdr.key_phase = (unmasked_b0 & 0x04) != 0;
    }

    let full_pn, pn_ok = decode_packet_number_checked(space.largest_recv_pn, trunc_pn, pn_len);
    guard pn_ok else { return false; }
    hdr.packet_number = full_pn;
    hdr.pn_length = pn_len;
    hdr.header_len = hdr.pn_offset + pn_len;
    let hdr_end = hdr.header_len as i64;
    guard hdr_end < work_pkt.len else { return false; }

    let aad = work_pkt[..hdr_end];
    let ciphertext = work_pkt[hdr_end..];
    return quic_aead_open_payload(space, full_pn, aad, ciphertext, out_plaintext);
}

inline fn get_dcid_len(len: i64) -> u8 {
    return len as u8;
}

inline fn conn_inc_packets_rx(conn: QuicConnection&) {
    conn.packets_rx = conn.packets_rx + 1;
}

// Reads a QUIC packet header before header protection removal by clearing masked reserved bits on byte 0
// when packet number space keys are installed (RFC 9001 §5.4).
//
// Example:
//   pkt_slice = [0xC5, 0x00, 0x00, 0x00, 0x01, ...], dcid_len = 8 (initial keys installed)
//   returns: QuicHeader { header_type: Initial, version: 1, ... }, ok = true
fn parse_quic_packet_pre_hp(conn: const QuicConnection&, pkt_slice: const u8[:], dcid_len: u8) -> QuicHeader, bool {
    guard pkt_slice.len > 0 else { return QuicHeader { .. }, false; }
    let b0 = pkt_slice[0];
    if (b0 & 0x80) != 0 {
        guard pkt_slice.len >= 5 else { return QuicHeader { .. }, false; }
        let ver = read_version_u32_be(pkt_slice);
        if ver == rfc::QUIC_VERSION_NEGOTIATION {
            return parse_quic_long_header(pkt_slice, b0);
        }
        let type_bits = (b0 >> 4) & 0x03;
        let ht, _ = quic_long_header_type(ver, type_bits);
        let sp_id = header_type_to_space_id(ht);
        let eff_b0 = if get_rx_space_keys_installed(conn, sp_id) { b0 & 0xF3 } else { b0 };
        return parse_quic_long_header(pkt_slice, eff_b0);
    }
    let eff_b0 = if conn.app_space.keys_installed { b0 & 0xE7 } else { b0 };
    return parse_quic_short_header(pkt_slice, eff_b0, dcid_len);
}

// Processes a single QUIC packet slice extracted from an inbound UDP datagram.
fn process_single_coalesced_packet(
    conn:      QuicConnection&,
    pkt_slice: const u8[:],
    now_us:    u64,
    out_ack:   AckFrame&,
) -> i64, bool, bool {
    guard conn.state != QuicConnState.Closing && conn.state != QuicConnState.Closed else {
        return 0, false, false;
    }

    let dcid_len = get_dcid_len(conn.scid.len);
    var hdr, ok = parse_quic_packet_pre_hp(conn, pkt_slice, dcid_len);
    guard ok else { return 0, false, false; }

    let pkt_wire_len, len_ok = calc_coalesced_packet_wire_len(pkt_slice, hdr);
    guard len_ok else { return 0, false, false; }

    if hdr.header_type == QuicHeaderType.VersionNegotiation || hdr.header_type == QuicHeaderType.Retry {
        let handled_pkt, needs_ack_pkt = dispatch_packet_type(conn, hdr, out_ack);
        guard handled_pkt else { return 0, false, false; }
        conn_inc_packets_rx(conn);
        return pkt_wire_len, true, needs_ack_pkt;
    }

    let space_id = header_type_to_space_id(hdr.header_type);
    var plaintext_payload: u8[..16384] = [];
    guard verify_and_decrypt_packet(conn, space_id, pkt_slice, pkt_wire_len, hdr, plaintext_payload) else {
        return 0, false, false;
    }

    let handled_frames, frame_ack_el = quic_conn_process_payload(conn, plaintext_payload[..], hdr.header_type, now_us);
    guard handled_frames else { return 0, false, false; }

    conn_inc_packets_rx(conn);
    bind_initial_server_cids(conn, hdr);
    if conn.state == QuicConnState.Closing || conn.state == QuicConnState.Closed {
        return pkt_wire_len, true, false;
    }
    let handled_pkt, needs_ack_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard handled_pkt else { return 0, false, false; }
    return pkt_wire_len, true, (needs_ack_pkt || frame_ack_el);
}

// RFC 9000 Section 12.2: Coalescing Packets - Processes an inbound UDP datagram containing one or more coalesced QUIC packets.
// Returns (handled: bool, needs_ack: bool).
fn quic_conn_process_datagram(
    conn:    QuicConnection&,
    dgram:   const u8[:],
    now_us:  u64,
    out_ack: AckFrame&,
) -> bool, bool {
    guard dgram.len > 0 else { return false, false; }
    conn.bytes_received = core::add_sat_u64(conn.bytes_received, dgram.len as u64);

    var offset: i64 = 0;
    var any_handled = false;
    var final_needs_ack = false;

    while offset < dgram.len {
        let rem = dgram[offset..];
        let consumed, handled, needs_ack = process_single_coalesced_packet(conn, rem, now_us, out_ack);
        guard handled && consumed > 0 else {
            return any_handled, final_needs_ack;
        }
        any_handled = true;
        if needs_ack {
            final_needs_ack = true;
        }
        offset += consumed;
    }

    return any_handled, final_needs_ack;
}
