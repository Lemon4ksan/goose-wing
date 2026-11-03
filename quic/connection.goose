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
    role:              QuicRole             = QuicRole.Server,
    state:             QuicConnState        = QuicConnState.Initial,
    scid:              u8[..20]             = [],
    dcid:              u8[..20]             = [],
    original_dcid:     u8[..20]             = [],
    initial_space:     PnSpaceState         = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    handshake_space:   PnSpaceState         = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    app_space:         PnSpaceState         = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    rtt:               RttState             = RttState { .. },
    pacer:             Pacer                = Pacer { .. },
    bbr:               BbrState             = BbrState { .. },
    stream_table:      QuicStreamTable      = QuicStreamTable { .. },
    flow_ctrl:         QuicFlowControl      = QuicFlowControl { .. },
    bytes_received:    u64                  = 0,
    bytes_sent:        u64                  = 0,
    validated_address: bool                 = false,
    packets_rx:        u64                  = 0,
    packets_tx:        u64                  = 0,
    close_code:        u64                  = 0,
    migration:         QuicMigrationManager = QuicMigrationManager { .. },
    dplpmtud:          Dplpmtud             = Dplpmtud { .. },
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
    conn.scid.append(scid);
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
    conn.dcid.append(server_dcid);
    conn.scid.append(client_scid);
    return conn;
}

inline fn calc_amplification_limit(rx: u64) -> u64 {
    return rx * 3;
}

inline fn is_within_amplification_budget(sent: u64, extra: u64, limit: u64) -> bool {
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
    space.has_sent_packets = true;
    if meta.pn > space.largest_sent_pn || space.sent_packets.len == 0 {
        space.largest_sent_pn = meta.pn;
    }
    guard space.sent_packets.len < space.sent_packets.cap else { return; }
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

fn match_pn_in_ack_ranges(pn: u64, ranges: const AckInterval[..64]&) -> bool {
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
    ranges: const AckInterval[..64]&,
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
            if pkt.pn == ranges[0].largest {
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

fn calc_lost_bytes(lost_pkts: const SentPacketMeta[..64]&) -> u64 {
    var lost_bytes: u64 = 0;
    for i in lost_pkts.len {
        if lost_pkts[i].in_flight {
            lost_bytes += lost_pkts[i].size_bytes;
        }
    }
    return lost_bytes;
}

// Processes a validated ACK frame in `space`, updating RTT, loss detection, and BBRv3 congestion control.
fn process_space_ack(
    conn:      QuicConnection&,
    space:     PnSpaceState&,
    ack_frame: const AckFrame&,
    now_us:    u64,
    is_app:    bool,
) -> bool {
    var acked_ranges: AckInterval[..64] = [];
    let ok = parse_and_validate_ack(space, ack_frame, acked_ranges);
    guard ok else {
        quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
        return false;
    }

    let acked_bytes, latest_rtt_us, in_flight_bytes, new_acked_pkts =
        mark_acked_packets_in_space(space, acked_ranges, now_us);

    if new_acked_pkts > 0 && latest_rtt_us > 0 {
        let ack_delay_us = ack_frame.ack_delay << 3;
        update_rtt(conn.rtt, latest_rtt_us, ack_delay_us, is_app && conn.state == QuicConnState.Established, now_us);
    }

    let eff_rtt = if latest_rtt_us > 0 { latest_rtt_us } else { conn.rtt.smoothed_rtt_us };
    if acked_bytes > 0 {
        let sample_bw = acked_bytes * 8000;
        if sample_bw > conn.bbr.bw_hi_bps {
            conn.bbr.bw_hi_bps = sample_bw;
        }
    }

    var lost_pkts: SentPacketMeta[..64] = [];
    let _ = detect_lost_packets(space, conn.rtt, now_us, lost_pkts);
    let lost_bytes = calc_lost_bytes(lost_pkts);

    bbr_check_probe_rtt(conn.bbr, now_us, eff_rtt);
    if lost_bytes > 0 || ack_frame.ecn_ce_count > 0 {
        bbr_on_congestion_signal(
            conn.bbr,
            in_flight_bytes,
            lost_bytes,
            acked_bytes,
            ack_frame.ecn_ce_count,
            new_acked_pkts,
        );
    } else if acked_bytes > 0 {
        bbr_advance_cycle(conn.bbr, true);
    }
    bbr_update_pacing_and_cwnd(conn.bbr);
    conn.pacer = conn.bbr.pacer;
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
    conn.bytes_sent = conn.bytes_sent + size_bytes;
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
    if hdr.header_type == QuicHeaderType.Initial {
        record_space_recv_packet(conn.initial_space, hdr.packet_number);
        let needs_ack = generate_space_ack(conn.initial_space, out_ack);
        return true, needs_ack;
    }

    if hdr.header_type == QuicHeaderType.Handshake {
        if conn.state == QuicConnState.Initial {
            conn.state = QuicConnState.Handshake;
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
    if hdr.payload_length > hdr.pn_length {
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
        quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 Section 19.8: STREAM Frames - Ingress STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, QUIC_ERR_STREAM_LIMIT);
        return false, false;
    }

    let end_offset = frame.offset + frame.length;
    guard validate_stream_recv_final_size(conn.stream_table.streams[idx], end_offset, frame.fin) else {
        quic_conn_close(conn, QUIC_ERR_FINAL_SIZE);
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
        quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 §19.4: Ingress RESET_STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, QUIC_ERR_STREAM_LIMIT);
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
        quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 §19.5: Ingress STOP_SENDING frame for unopened locally-initiated stream is STREAM_STATE_ERROR
    if !is_peer_initiated_stream(frame.stream_id, conn.role) {
        let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
        guard sid_found >= 0 else {
            quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
            return false, false;
        }
    }

    let idx, ok = quic_table_get_or_open_stream(conn.stream_table, frame.stream_id, conn.flow_ctrl.local_window_size);
    guard ok else {
        quic_conn_close(conn, QUIC_ERR_STREAM_LIMIT);
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
            quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
            return false, false;
        }
        // RFC 9000 §19.10: Ingress MAX_STREAM_DATA frame for unopened locally-initiated stream is STREAM_STATE_ERROR
        if !is_peer_initiated_stream(frame.stream_id, conn.role) {
            let sid_found = quic_table_find_stream(conn.stream_table, frame.stream_id);
            guard sid_found >= 0 else {
                quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
                return false, false;
            }
        }
        let idx = quic_table_find_stream(conn.stream_table, frame.stream_id);
        if idx >= 0 {
            quic_fc_update_stream_send_max_data(conn.stream_table.streams[idx], frame.max_data);
        }
        return true, true;
    }

    if frame.frame_type == QuicFrameType.StreamDataBlocked {
        // RFC 9000 §19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only
        // stream MUST terminate the connection with error STREAM_STATE_ERROR."
        guard quic_stream_can_recv(frame.stream_id, conn.role) else {
            quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
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
            quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        return true, true;
    }
    if frame.frame_type == QuicFrameType.RetireConnectionId {
        // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
        if conn.scid.len == 0 {
            quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
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
            quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }
        conn.state = QuicConnState.Established;
        return true, true;
    }
    if frame.frame_type == QuicFrameType.NewToken {
        // RFC 9000 §19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt
        // of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
        if conn.role == QuicRole.Server {
            quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
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
    return true, true;
}

fn dispatch_inbound_frame(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    if frame.frame_type == QuicFrameType.Padding {
        return true, false;
    }
    if frame.frame_type == QuicFrameType.Ping {
        return true, true;
    }
    if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
        return true, false;
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
        || frame.frame_type == QuicFrameType.StreamDataBlocked {
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
            || ftype == QuicFrameType.PathResponse
            || ftype == QuicFrameType.RetireConnectionId {
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
    let ack_f = AckFrame {
        is_ecn:          frame.frame_type == QuicFrameType.AckEcn,
        largest_acked:   frame.offset,
        ack_delay:       frame.max_data,
        first_ack_range: frame.length,
        ..
    };
    let space_id = header_type_to_space_id(htype);
    var has_sent = conn.app_space.has_sent_packets;
    if space_id == PnSpaceId.Initial {
        has_sent = conn.initial_space.has_sent_packets;
    } else if space_id == PnSpaceId.Handshake {
        has_sent = conn.handshake_space.has_sent_packets;
    }
    guard has_sent else { return true; }
    return quic_conn_on_ack(conn, ack_f, now_us, space_id);
}

fn quic_conn_process_payload(
    conn:    QuicConnection&,
    payload: const u8[:],
    htype:   QuicHeaderType = QuicHeaderType.OneRtt,
    now_us:  u64            = 100000,
) -> bool, bool {
    // RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
    guard payload.len > 0 else {
        quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
        return false, false;
    }
    var idx: i64 = 0;
    var any_ack_el = false;

    while idx < payload.len {
        let frame, ok = decode_quic_frame_cursor(payload, idx);
        guard ok else {
            quic_conn_close(conn, QUIC_ERR_FRAME_ENCODING);
            return false, false;
        }

        guard quic_is_frame_allowed_in_packet(frame.frame_type, htype) else {
            quic_conn_close(conn, QUIC_ERR_PROTOCOL_VIOLATION);
            return false, false;
        }

        if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
            guard dispatch_inbound_ack_frame(conn, frame, htype, now_us) else {
                return false, false;
            }
        }

        let handled, ack_el = dispatch_inbound_frame(conn, frame);
        guard handled else { return false, false; }
        if ack_el {
            any_ack_el = true;
        }
    }

    return true, any_ack_el;
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

// Processes a single QUIC packet slice extracted from an inbound UDP datagram.
fn process_single_coalesced_packet(
    conn:      QuicConnection&,
    pkt_slice: const u8[:],
    now_us:    u64,
    out_ack:   AckFrame&,
) -> i64, bool, bool {
    let dcid_len: u8 = conn.scid.len as u8;
    let hdr, ok = parse_quic_header(pkt_slice, dcid_len);
    guard ok else { return 0, false, false; }

    let pkt_wire_len, len_ok = calc_coalesced_packet_wire_len(pkt_slice, hdr);
    guard len_ok else { return 0, false, false; }

    conn.packets_rx = conn.packets_rx + 1;
    bind_initial_server_cids(conn, hdr);
    let handled_pkt, needs_ack_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard handled_pkt else { return 0, false, false; }

    if hdr.header_type == QuicHeaderType.VersionNegotiation || hdr.header_type == QuicHeaderType.Retry {
        return pkt_wire_len, true, needs_ack_pkt;
    }

    let payload = get_packet_payload(pkt_slice[..pkt_wire_len], hdr);
    if hdr.payload_length > hdr.pn_length && payload.len == 0 {
        return 0, false, false;
    }
    let handled_frames, frame_ack_el = quic_conn_process_payload(conn, payload, hdr.header_type, now_us);
    guard handled_frames else { return 0, false, false; }

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
    conn.bytes_received = conn.bytes_received + (dgram.len as u64);

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
