// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// RFC 9000 / RFC 9002: QUIC Connection State Machine, Anti-Amplification, and Packet Space Dispatcher
import std;
import core from "../..";
import wing from "../..";

fn test_quic_anti_amplification() {
    var server = wing::new_quic_server_connection("server_cid_01");

    // Server has received 0 bytes: cannot send anything
    let can_send_0 = wing::quic_conn_can_send(server, 1200);
    print("AA_INIT: can_send_1200=", can_send_0, "\n");
    // CHECK: AA_INIT: can_send_1200=false

    // Simulate receiving 1200-byte client datagram (RFC 9000 §8.1: budget = 3 * 1200 = 3600)
    server.bytes_received = 1200;
    let can_send_3600 = wing::quic_conn_can_send(server, 3600);
    let can_send_3601 = wing::quic_conn_can_send(server, 3601);
    print("AA_BUDGET: can_3600=", can_send_3600, " can_3601=", can_send_3601, "\n");
    // CHECK: AA_BUDGET: can_3600=true can_3601=false

    // Send 3000 bytes: remaining budget is 600
    server.bytes_sent = 3000;
    let can_send_600 = wing::quic_conn_can_send(server, 600);
    let can_send_601 = wing::quic_conn_can_send(server, 601);
    print("AA_CONSUMED: can_600=", can_send_600, " can_601=", can_send_601, "\n");
    // CHECK: AA_CONSUMED: can_600=true can_601=false

    // Address validated: limit lifted
    server.validated_address = true;
    let can_send_unlimited = wing::quic_conn_can_send(server, 100000);
    print("AA_VALIDATED: can_unlimited=", can_send_unlimited, "\n");
    // CHECK: AA_VALIDATED: can_unlimited=true
}

fn test_quic_pn_space_segregation() {
    var conn = wing::new_quic_server_connection("scid_123");

    // Send in Initial space
    wing::quic_conn_record_sent(conn, wing::PnSpaceId.Initial, 0, 1200, true, 1000);
    wing::quic_conn_record_sent(conn, wing::PnSpaceId.Initial, 1, 1200, true, 1050);

    // Send in Handshake space
    wing::quic_conn_record_sent(conn, wing::PnSpaceId.Handshake, 0, 800, true, 1100);

    // Send in ApplicationData space
    wing::quic_conn_record_sent(conn, wing::PnSpaceId.ApplicationData, 0, 1400, true, 1200);

    print("PN_SPACES: init_largest=", conn.initial_space.largest_sent_pn,
          " hs_largest=", conn.handshake_space.largest_sent_pn,
          " app_largest=", conn.app_space.largest_sent_pn,
          " total_tx_pkts=", conn.packets_tx,
          " total_tx_bytes=", conn.bytes_sent, "\n");
    // CHECK: PN_SPACES: init_largest=1 hs_largest=0 app_largest=0 total_tx_pkts=4 total_tx_bytes=4600
}

fn test_quic_datagram_ack_generation() {
    var conn = wing::new_quic_server_connection("server_cid_01");

    // Construct valid wire Initial packet
    var initial_pkt: u8[..128] = [];
    initial_pkt.push(0xC0); // Long header, Initial type (0), PN len 1
    // Version 1: 0x00000001
    initial_pkt.push(0x00); initial_pkt.push(0x00); initial_pkt.push(0x00); initial_pkt.push(0x01);
    // DCID len = 8, DCID = 0102030405060708
    initial_pkt.push(8);
    for b in 8 { initial_pkt.push((b + 1) as u8); }
    // SCID len = 8, SCID = 0807060504030201
    initial_pkt.push(8);
    for b in 8 { initial_pkt.push((8 - b) as u8); }
    // Token len = 0 (VarInt)
    initial_pkt.push(0);
    // Length = 4 (VarInt)
    initial_pkt.push(4);
    // Packet Number = 0
    initial_pkt.push(0);
    // Payload (PING frame: 0x01)
    initial_pkt.push(0x01);
    initial_pkt.push(0x00);
    initial_pkt.push(0x00);

    var ack_frame = wing::AckFrame { .. };
    let handled, needs_ack = wing::quic_conn_process_datagram(conn, initial_pkt[..], 2000, ack_frame);

    print("DGRAM_INIT: handled=", handled, " needs_ack=", needs_ack, " largest_acked=", ack_frame.largest_acked, "\n");
    // CHECK: DGRAM_INIT: handled=true needs_ack=true largest_acked=0
}

fn test_quic_connection_close() {
    var conn = wing::new_quic_server_connection("scid_close");
    wing::quic_conn_advance_state(conn, wing::QuicConnState.Established);

    print("CONN_ESTABLISHED: state=", conn.state == wing::QuicConnState.Established, "\n");
    // CHECK: CONN_ESTABLISHED: state=true

    // Trigger connection close with APPLICATION_ERROR
    wing::quic_conn_close(conn, wing::QUIC_ERR_APPLICATION_ERROR);
    print("CONN_CLOSED: state=", conn.state == wing::QuicConnState.Closing, " code=", conn.close_code, "\n");
    // CHECK: CONN_CLOSED: state=true code=12
}

fn main() {
    print("=== LIT QUIC Connection Engine Verification ===\n");
    test_quic_anti_amplification();
    test_quic_pn_space_segregation();
    test_quic_datagram_ack_generation();
    test_quic_connection_close();
}
