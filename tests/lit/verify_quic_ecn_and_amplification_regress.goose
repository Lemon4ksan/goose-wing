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

fn test_grease_quic_bit_rfc9287() {
    var conn = internal::new_quic_server_connection("scid");
    // Short header with Fixed Bit (0x40) cleared: 0x00, DCID="scid", PN=0x01, PING frame (0x01)
    let greased_pkt: u8[7] = [0x00, 's', 'c', 'i', 'd', 0x01, 0x01];
    let _, ok_disabled = internal::parse_quic_packet_pre_hp(conn, greased_pkt[..], 4);
    assert(!ok_disabled);

    conn.allow_grease_quic_bit = true;
    let hdr_enabled, ok_enabled = internal::parse_quic_packet_pre_hp(conn, greased_pkt[..], 4);
    assert(ok_enabled && hdr_enabled.header_type == internal::QuicHeaderType.OneRtt);

    var out_ack = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(conn, greased_pkt[..], 2000, out_ack);
    assert(handled && needs_ack);
    print("GREASE_QUIC_BIT: OK");
}

fn test_stateless_reset_codec_and_detection() {
    var conn = internal::new_quic_client_connection("dcid", "scid");
    conn.state = internal::QuicConnState.Established;
    let token: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    var ncid_buf: u8[..64] = [];
    assert(internal::encode_new_conn_id_frame(ncid_buf, 1, 0, "ncid", token));
    let ok_pl, _ = internal::quic_conn_process_payload(conn, ncid_buf[..], internal::QuicHeaderType.OneRtt, 1000);
    assert(ok_pl && conn.peer_reset_tokens.len == 1);

    var sr_pkt: u8[..64] = [];
    let short_rand: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
    assert(!internal::encode_stateless_reset_packet(sr_pkt, short_rand[..], token));

    let rand_bytes: u8[6] = [0xFF, 0x11, 0x22, 0x33, 0x44, 0x55];
    assert(internal::encode_stateless_reset_packet(sr_pkt, rand_bytes[..], token));
    assert(sr_pkt.len == 22 && (sr_pkt[0] & 0xC0) == 0x40);
    assert(internal::is_stateless_reset_datagram(conn, sr_pkt[..]));

    // Install dummy 1-RTT keys so AEAD decryption fails on the stateless reset packet and triggers closure
    let dummy_hp:  u8[16] = [0x11; 16];
    let dummy_key: u8[16] = [0x22; 16];
    let dummy_iv:  u8[12] = [0x33; 12];
    assert(internal::quic_install_pn_space_keys(conn.app_space, dummy_hp[..], dummy_key[..], dummy_iv[..], 0x1301));

    var out_ack = internal::AckFrame { .. };
    let handled, _ = internal::quic_conn_process_datagram(conn, sr_pkt[..], 3000, out_ack);
    assert(!handled && conn.state == internal::QuicConnState.Closed);
    let _ = internal::quic_conn_on_probe_lost(conn, 1400);
    print("STATELESS_RESET_DETECTION: OK");
}

fn test_ecn_validation_and_blackhole_detection() {
    var space = internal::PnSpaceState { space_id: internal::PnSpaceId.ApplicationData, .. };
    let p0 = internal::SentPacketMeta {
        pn:            0,
        time_sent_us:  1000,
        size_bytes:    1200,
        ack_eliciting: true,
        in_flight:     true,
        ecn_marked:    true,
    };
    let p1 = internal::SentPacketMeta {
        pn:            1,
        time_sent_us:  2000,
        size_bytes:    1200,
        ack_eliciting: true,
        in_flight:     true,
        ecn_marked:    true,
    };
    internal::record_space_sent_packet(space, p0);
    internal::record_space_sent_packet(space, p1);
    assert(space.tx_ect0_sent == 2);

    var valid_ack = internal::AckFrame { is_ecn: true, largest_acked: 0, ect0_count: 1, ect1_count: 0, ecn_ce_count: 0, .. };
    let ok1, ce1 = internal::validate_space_ecn(space, valid_ack, 1);
    assert(ok1 && ce1 == 0 && space.ecn_state == internal::QuicEcnState.Capable);

    // Bleaching attack: ECN-marked packet 1 acknowledged by non-ECN ACK frame
    var bleached_ack = internal::AckFrame { is_ecn: false, largest_acked: 1, .. };
    let ok2, _ = internal::validate_space_ecn(space, bleached_ack, 1);
    assert(!ok2 && space.ecn_state == internal::QuicEcnState.Failed);
    print("ECN_VALIDATION_STATE_MACHINE: OK");
}

fn test_two_pointer_ack_sweep_and_loss_compaction() {
    var space = internal::PnSpaceState { space_id: internal::PnSpaceId.ApplicationData, .. };
    for pn in 6 {
        let pkt = internal::SentPacketMeta {
            pn:            pn as u64,
            time_sent_us:  1000 + (pn as u64) * 100,
            size_bytes:    1000,
            ack_eliciting: true,
            in_flight:     true,
            ecn_marked:    (pn % 2) == 0,
        };
        internal::record_space_sent_packet(space, pkt);
    }
    var ranges: internal::AckInterval[..65] = [];
    ranges.push(internal::AckInterval { smallest: 4, largest: 5 });
    ranges.push(internal::AckInterval { smallest: 1, largest: 2 });
    let acked_b, _, inflight_b, acked_cnt, ecn_cnt = internal::mark_acked_packets_in_space(space, ranges, 5000);
    assert(acked_cnt == 4 && ecn_cnt == 2 && acked_b == 4000 && inflight_b == 2000 && space.sent_packets.len == 2);

    var lost: internal::SentPacketMeta[..128] = [];
    let rtt = internal::RttState { latest_rtt_us: 10000, smoothed_rtt_us: 10000, .. };
    assert(internal::detect_lost_packets(space, rtt, 5000, lost));
    // PN 0 (5 >= 0 + 3) and PN 3 (5 < 3 + 3, not lost by pkt threshold if time < lost_send_time)
    assert(lost.len == 1 && lost[0].pn == 0 && space.sent_packets.len == 1 && space.sent_packets[0].pn == 3);
    print("TWO_POINTER_ACK_AND_LOSS: OK");
}

fn test_batch_hp_masks() {
    let hp_key: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    var samples:   u8[16][2] = [[0xAA; 16], [0x55; 16]];
    var out_masks: u8[5][2]  = [[0; 5], [0; 5]];
    let count = internal::compute_quic_hp_masks_batch(rfc::TLS_CIPHER_AES_128_GCM_SHA256, hp_key[..], samples[..], out_masks[..]);
    let single0 = internal::aes128_header_protect_mask(hp_key, samples[0]);
    let single1 = internal::aes128_header_protect_mask(hp_key, samples[1]);
    assert(count == 2 && out_masks[0][..] == single0[..] && out_masks[1][..] == single1[..]);
    print("BATCH_HP_MASKS: OK");
}

fn main() {
    test_regress_anti_amplification_overflow();
    test_regress_long_header_zero_payload_bounded();
    test_regress_ecn_ce_cumulative_and_bbr_cycle();
    test_regress_conn_traffic_counter_saturation();
    test_grease_quic_bit_rfc9287();
    test_stateless_reset_codec_and_detection();
    test_ecn_validation_and_blackhole_detection();
    test_two_pointer_ack_sweep_and_loss_compaction();
    test_batch_hp_masks();
}

// CHECK: REGRESS_AMPLIFICATION_OVERFLOW: OK
// CHECK: REGRESS_ZERO_PAYLOAD_BOUNDED: OK
// CHECK: REGRESS_ECN_CE_CYCLE_ADVANCE: OK
// CHECK: REGRESS_COUNTER_SATURATION: OK
// CHECK: GREASE_QUIC_BIT: OK
// CHECK: STATELESS_RESET_DETECTION: OK
// CHECK: ECN_VALIDATION_STATE_MACHINE: OK
// CHECK: TWO_POINTER_ACK_AND_LOSS: OK
// CHECK: BATCH_HP_MASKS: OK
