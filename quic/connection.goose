// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic QUIC Connection Engine, Packet Number Spaces,
// Loss Recovery Coordinator, and Path Validation Reactor (RFC 9000, RFC 9002).
namespace wing;

import std;
import core from "..";
import quic.packet;
import quic.AckFrame;
import quic.bbr;

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
    role: QuicRole = QuicRole.Server,
    state: QuicConnState = QuicConnState.Initial,
    scid: u8[..20] = [],
    dcid: u8[..20] = [],
    original_dcid: u8[..20] = [],
    initial_space: PnSpaceState = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    handshake_space: PnSpaceState = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    app_space: PnSpaceState = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    rtt: RttState = RttState { .. },
    pacer: Pacer = Pacer { .. },
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    validated_address: bool = false,
    packets_rx: u64 = 0,
    packets_tx: u64 = 0,
    close_code: u64 = 0,
}

fn new_quic_server_connection(scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role: QuicRole.Server,
        state: QuicConnState.Initial,
        validated_address: false,
        ..
    };
    conn.scid.append(scid);
    return conn;
}

fn new_quic_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role: QuicRole.Client,
        state: QuicConnState.Initial,
        validated_address: true, // Client address validation is implicit
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

// RFC 9000 §8.1: Server anti-amplification limit (3x bytes received)
fn quic_conn_can_send(conn: const QuicConnection&, bytes: u64) -> bool {
    guard !conn.validated_address && conn.role == QuicRole.Server else {
        return true;
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
    if space.sent_packets.len < space.sent_packets.cap {
        space.sent_packets.push(meta);
    }
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
    conn: QuicConnection&,
    space_id: PnSpaceId,
    pn: u64,
    size_bytes: u64,
    ack_eliciting: bool,
    now_us: u64,
) {
    inc_conn_sent_bytes(conn, size_bytes);
    inc_conn_tx_packets(conn);

    let meta = SentPacketMeta {
        pn: pn,
        time_sent_us: now_us,
        size_bytes: size_bytes,
        ack_eliciting: ack_eliciting,
        in_flight: ack_eliciting,
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

// Processes an inbound UDP datagram containing QUIC packets.
// Returns (handled: bool, needs_ack: bool).
fn quic_conn_process_datagram(
    conn: QuicConnection&,
    dgram: const u8[:],
    now_us: u64,
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
    return dispatch_packet_type(conn, hdr, out_ack);
}
