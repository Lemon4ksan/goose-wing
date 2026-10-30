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
        validated_address: false,
        stream_table:      new_quic_stream_table(QuicRole.Server),
        flow_ctrl:         new_quic_flow_control(65536, 65536),
        ..
    };
    conn.scid.append(scid);
    return conn;
}

fn new_quic_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role:              QuicRole.Client,
        state:             QuicConnState.Initial,
        validated_address: true, // Client address validation is implicit
        stream_table:      new_quic_stream_table(QuicRole.Client),
        flow_ctrl:         new_quic_flow_control(65536, 65536),
        ..
    };
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

inline fn inc_conn_sent_bytes(conn: QuicConnection&, size_bytes: u64) {
    conn.bytes_sent = conn.bytes_sent + size_bytes;
}

inline fn inc_conn_tx_packets(conn: QuicConnection&) {
    conn.packets_tx = conn.packets_tx + 1;
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
    inc_conn_sent_bytes(conn, size_bytes);
    inc_conn_tx_packets(conn);

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

inline fn inc_conn_recv_bytes(conn: QuicConnection&, dgram_len: i64) {
    conn.bytes_received = conn.bytes_received + (dgram_len as u64);
}

inline fn inc_conn_rx_packets(conn: QuicConnection&) {
    conn.packets_rx = conn.packets_rx + 1;
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

inline fn calc_payload_offset(hdr_len: u32) -> i64 {
    return hdr_len;
}

inline fn calc_bounded_payload_len(total_len: u64, pn_len: u8) -> i64 {
    let sub = total_len - pn_len;
    return sub as i64;
}

inline fn calc_payload_end(start: i64, bounded_len: i64, dgram_len: i64) -> i64 {
    let end = start + bounded_len;
    if end <= dgram_len { return end; }
    return dgram_len;
}

inline fn get_bounded_payload(
    dgram:       const u8[:],
    start:       i64,
    payload_len: u64,
    pn_len:      u8,
) -> u8[:] {
    let blen = calc_bounded_payload_len(payload_len, pn_len);
    let end = start + blen;
    guard end <= dgram.len else { return dgram[..0]; }
    return dgram[start..end];
}

fn get_packet_payload(dgram: const u8[:], hdr: const QuicHeader&) -> u8[:] {
    let start = calc_payload_offset(hdr.header_len);
    guard start <= dgram.len else { return dgram[..0]; }
    if hdr.payload_length > hdr.pn_length {
        return get_bounded_payload(dgram, start, hdr.payload_length, hdr.pn_length);
    }
    return dgram[start..];
}

fn dispatch_stream_inbound(conn: QuicConnection&, frame: const QuicFrame&) -> bool, bool {
    guard quic_stream_can_recv(frame.stream_id, conn.role) else {
        quic_conn_close(conn, QUIC_ERR_STREAM_STATE);
        return false, false;
    }

    // RFC 9000 §19.8: Ingress STREAM frame for unopened locally-initiated stream is STREAM_STATE_ERROR
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

fn quic_conn_process_payload(
    conn:    QuicConnection&,
    payload: const u8[:],
    htype:   QuicHeaderType = QuicHeaderType.OneRtt,
) -> bool, bool {
    guard payload.len > 0 else { return true, false; }
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

        let handled, ack_el = dispatch_inbound_frame(conn, frame);
        guard handled else { return false, false; }
        if ack_el {
            any_ack_el = true;
        }
    }

    return true, any_ack_el;
}

// Processes an inbound UDP datagram containing QUIC packets.
// Returns (handled: bool, needs_ack: bool).
fn quic_conn_process_datagram(
    conn:    QuicConnection&,
    dgram:   const u8[:],
    now_us:  u64,
    out_ack: AckFrame&,
) -> bool, bool {
    guard dgram.len > 0 else { return false, false; }
    inc_conn_recv_bytes(conn, dgram.len);
    inc_conn_rx_packets(conn);

    // Parse packet header
    let dcid_len: u8 = conn.scid.len as u8;
    let hdr, ok = parse_quic_header(dgram, dcid_len);
    guard ok else { return false, false; }

    bind_initial_server_cids(conn, hdr);
    let handled_pkt, needs_ack_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard handled_pkt else { return false, false; }

    let payload = get_packet_payload(dgram, hdr);
    if hdr.payload_length > hdr.pn_length && payload.len == 0 {
        return false, false;
    }
    let handled_frames, frame_ack_el = quic_conn_process_payload(conn, payload, hdr.header_type);
    guard handled_frames else { return false, false; }

    let final_needs_ack = needs_ack_pkt || frame_ack_el;
    return true, final_needs_ack;
}
