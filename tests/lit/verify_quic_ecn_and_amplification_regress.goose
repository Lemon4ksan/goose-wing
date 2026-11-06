// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_ecn_and_amplification_regress.goose
// Regression test suite for QUIC bug hunter audit findings:
// - Cumulative ECN-CE handling and BBR cycle unfreeze (RFC 9002 §7.3.2)
// - Server anti-amplification arithmetic overflow protection (RFC 9000 §8.1)
// - Long Header packet with zero payload bounds safety (RFC 9000 §17.2)
// - Connection cumulative byte counter saturation (GOOSE-BUG-3)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_regress_anti_amplification_overflow() {
    // 1. rx * 3 overflow protection
    let rx_large: u64 = 0x6000000000000000; // > 0xFFFFFFFFFFFFFFFF / 3
    let limit = internal::calc_amplification_limit(rx_large);
    assert(limit >= rx_large); // Must saturate to u64::MAX, not wrap!

    // 2. sent + extra overflow protection
    let sent_large: u64 = 0xFFFFFFFFFFFFFFFE;
    let extra:      u64 = 100;
    let budget_ok = internal::is_within_amplification_budget(sent_large, extra, 1000);
    assert(!budget_ok); // Must reject wrapped overflow!
    print("REGRESS_AMPLIFICATION_OVERFLOW: OK");
}

fn test_regress_long_header_zero_payload_bounded() {
    var dgram: u8[32] = [0; 32];
    for i in 32 { dgram[i] = (i + 1) as u8; }

    var hdr = internal::QuicHeader {
        header_type:    internal::QuicHeaderType.Initial,
        header_len:     10,
        pn_length:      2,
        payload_length: 2, // plen == pn_length -> 0 bytes payload!
        ..
    };
    let pl = internal::get_packet_payload(dgram[..], hdr);
    assert(pl.len == 0); // Must be empty slice, not dgram[10..]!
    print("REGRESS_ZERO_PAYLOAD_BOUNDED: OK");
}

fn test_regress_ecn_ce_cumulative_and_bbr_cycle() {
    var conn = internal::new_quic_server_connection("scid");
    conn.state = internal::QuicConnState.Established;

    // Send packet 0 in ApplicationData space
    let m0 = internal::SentPacketMeta {
        pn:            0,
        time_sent_us:  1000,
        size_bytes:    1200,
        ack_eliciting: true,
        in_flight:     true,
    };
    internal::record_space_sent_packet(conn.app_space, m0);

    // First ACK with ECN-CE = 1 acknowledges packet 0, round is done
    var ack1 = internal::AckFrame {
        is_ecn:          true,
        largest_acked:   0,
        ack_delay:       0,
        first_ack_range: 0,
        ecn_ce_count:    1,
        ..
    };
    let ok1 = internal::quic_conn_on_ack(conn, ack1, 100000, internal::PnSpaceId.ApplicationData);
    assert(ok1);

    // Send packet 1
    let m1 = internal::SentPacketMeta {
        pn:            1,
        time_sent_us:  2000,
        size_bytes:    1200,
        ack_eliciting: true,
        in_flight:     true,
    };
    internal::record_space_sent_packet(conn.app_space, m1);

    // Second ACK with same cumulative ECN-CE = 1 acknowledges packet 1, round is done
    var ack2 = internal::AckFrame {
        is_ecn:          true,
        largest_acked:   1,
        ack_delay:       0,
        first_ack_range: 0,
        ecn_ce_count:    1,
        ..
    };
    let ok2 = internal::quic_conn_on_ack(conn, ack2, 110000, internal::PnSpaceId.ApplicationData);
    assert(ok2);

    // When no NEW ECN marks arrive, BBR should advance its cycle (Startup -> Drain).
    assert(conn.bbr.mode != internal::BbrMode.Startup);
    print("REGRESS_ECN_CE_CYCLE_ADVANCE: OK");
}

fn test_regress_conn_traffic_counter_saturation() {
    var conn = internal::new_quic_server_connection("scid");
    conn.bytes_received = 0xFFFFFFFFFFFFFFF0;
    var dgram: u8[32] = [0; 32];
    var ack = internal::AckFrame { .. };
    let _ = internal::quic_conn_process_datagram(conn, dgram[..], 1000, ack);
    assert(conn.bytes_received >= 0xFFFFFFFFFFFFFFF0);
    print("REGRESS_COUNTER_SATURATION: OK");
}

fn main() {
    test_regress_anti_amplification_overflow();
    test_regress_long_header_zero_payload_bounded();
    test_regress_ecn_ce_cumulative_and_bbr_cycle();
    test_regress_conn_traffic_counter_saturation();
}

// CHECK: REGRESS_AMPLIFICATION_OVERFLOW: OK
// CHECK: REGRESS_ZERO_PAYLOAD_BOUNDED: OK
// CHECK: REGRESS_ECN_CE_CYCLE_ADVANCE: OK
// CHECK: REGRESS_COUNTER_SATURATION: OK
