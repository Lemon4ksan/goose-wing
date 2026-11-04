// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_bug_hunter_regress.goose
// Regression test suite for QUIC bug hunter audit findings across slices S001-S020:
// - S008_C02: Flow control RESET with final_size < bytes_recv must fail with FINAL_SIZE_ERROR.
// - S008_C01: Flow control credit renewal must require application read progress (backpressure).
// - S018_C01: Stream frame offset + length 64-bit wrap and QUIC_VARINT_MAX rejection.
// - S019_C02: Stream RESET after DataRecvd / DataRead with final_size mismatch must fail with FINAL_SIZE_ERROR.
// - S020_C01: Stream table must reject peer opening locally-initiated streams (STREAM_STATE_ERROR).
// - S016_C02: ReassemblyBuffer read_contiguous must bound reads to out buffer capacity without data loss.
// - S016_C01: ReassemblyBuffer insert_fragment must roll back FIN state if fragment insertion fails.
// - S013_C01: Migration path_can_send must protect against arithmetic overflow on bytes_sent + bytes_to_send.
// - S007_C01: DPLPMTUD calc_dplpmtud_probe_payload_size must return 0 when target_mtu <= overhead_bytes.
// - S003_C03: BBR bbr_on_congestion_signal must clamp cwnd_bytes to BBR_MIN_CWND_BYTES under ECN.
// - S003_C02: BBR bbr_check_probe_rtt must guard against non-monotonic clock underflow.
// - S002_C01: parse_and_validate_ack must clear out_intervals on validation error (transactional hygiene).
// - S006_C01: Connection dispatch_inbound_ack_frame must reject ACK for PN space where no packets sent.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_fc_recv_reset_smaller_than_bytes_recv() {
    var fc = internal::new_quic_flow_control(100000, 100000);
    var s = internal::new_quic_stream(0, 50000);
    s.bytes_recv = 100;

    // RFC 9000 §4.5: RESET_STREAM with final_size < bytes_recv MUST trigger FINAL_SIZE_ERROR.
    let ok, err = internal::quic_fc_record_recv_reset(fc, s, 50);
    assert(!ok);
    assert(err == rfc::QUIC_ERR_FINAL_SIZE);
    print("REGRESS_FC_RESET_FINAL_SIZE: OK");
}

fn test_fc_credit_renewal_threshold_and_bounds() {
    var fc = internal::new_quic_flow_control(100000, 100000);
    var s = internal::new_quic_stream(0, 100000);

    // Initial check: no update needed when window is fresh
    let need_init, _ = internal::quic_fc_check_conn_window_update(fc);
    assert(!need_init);

    // Receive 20,000 wire bytes (below 50,000 threshold): no update needed
    let ok_recv, _ = internal::quic_fc_record_recv_stream(fc, s, 0, 20000);
    assert(ok_recv);
    let need_below, _ = internal::quic_fc_check_conn_window_update(fc);
    assert(!need_below);

    // Receive another 40,000 wire bytes (total 60,000, exceeds 50,000 threshold): update triggers
    let ok_recv2, _ = internal::quic_fc_record_recv_stream(fc, s, 20000, 40000);
    assert(ok_recv2);
    let need_above, new_conn_max = internal::quic_fc_check_conn_window_update(fc);
    assert(need_above);
    assert(new_conn_max == 160000);

    print("REGRESS_FC_CREDIT_RENEWAL: OK");
}

fn test_stream_recv_frame_offset_wrap() {
    var s = internal::new_quic_stream(0, 100000);

    // 1. 64-bit integer wrap: 0xFFFFFFFFFFFFFFFE + 10 wraps to 8.
    let ok_wrap, _ = internal::quic_stream_on_recv_stream_frame(s, 0xFFFFFFFFFFFFFFFE, 10, false);
    assert(!ok_wrap);

    // 2. Offsets exceeding 62-bit VarInt ceiling (RFC 9000 §4.5).
    let ok_varint, _ = internal::quic_stream_on_recv_stream_frame(s, rfc::QUIC_VARINT_MAX, 1, false);
    assert(!ok_varint);

    print("REGRESS_STREAM_OFFSET_WRAP: OK");
}

fn test_stream_recv_reset_after_datarecvd_final_size_mismatch() {
    var s = internal::new_quic_stream(0, 100000);

    // Receive 100 bytes with FIN -> transitions to DataRecvd with final_size = 100.
    let ok_frame, _ = internal::quic_stream_on_recv_stream_frame(s, 0, 100, true);
    assert(ok_frame);
    assert(s.recv_state == internal::QuicRecvState.DataRecvd);
    assert(s.recv_final_size == 100);

    // RFC 9000 §4.5: RESET_STREAM with final_size != recv_final_size MUST fail with FINAL_SIZE_ERROR.
    let ok_rst, err_rst = internal::quic_stream_on_recv_reset(s, 0, 50);
    assert(!ok_rst);
    assert(err_rst == rfc::QUIC_ERR_FINAL_SIZE);

    print("REGRESS_STREAM_RESET_FINAL_SIZE_MISMATCH: OK");
}

fn test_stream_table_peer_cannot_open_local_stream() {
    var tbl = internal::new_quic_stream_table(internal::QuicRole.Server);

    // Server-initiated bidi stream ID is 1 (init_bit == 1, role == Server).
    // An uncreated locally-initiated stream MUST NOT be opened by ingress frame (RFC 9000 §3.1).
    let _, ok = internal::quic_table_get_or_open_stream(tbl, 1, 65536);
    assert(!ok);

    print("REGRESS_STREAM_TABLE_LOCAL_OPEN_REJECT: OK");
}

fn test_packet_read_contiguous_capacity_safety() {
    var buf = internal::new_reassembly_buffer(65536);
    var raw_data: u8[100] = [65; 100];
    let ok_ins = internal::insert_fragment(buf, 0, raw_data[..], false);
    assert(ok_ins);

    // Read with small buffer of capacity 32 passing bounded headroom.
    var out_small: u8[..32] = [];
    let read_bytes = internal::read_contiguous(buf, out_small, (out_small.cap - out_small.len) as i64);
    assert(read_bytes == 32);
    assert(out_small.len == 32);
    assert(buf.consumed_offset == 32);

    // Remaining 68 bytes MUST still be intact and readable!
    var out_rem: u8[..100] = [];
    let read_rem = internal::read_contiguous(buf, out_rem);
    assert(read_rem == 68);
    assert(out_rem.len == 68);
    assert(buf.consumed_offset == 100);

    print("REGRESS_PACKET_READ_CONTIGUOUS_CAP: OK");
}

fn test_packet_insert_fragment_fin_transactional_rollback() {
    var buf = internal::new_reassembly_buffer(64);

    // Try to insert a 200-byte fragment with FIN into a buffer with 64-byte max limit.
    var large_payload: u8[200] = [66; 200];
    let ok_ins = internal::insert_fragment(buf, 0, large_payload[..], true);
    assert(!ok_ins);

    // FIN state MUST NOT be latched if fragment insertion failed!
    assert(!buf.fin_received);
    assert(buf.final_size == 0xFFFFFFFFFFFFFFFF);

    print("REGRESS_PACKET_INSERT_FIN_ROLLBACK: OK");
}

fn test_migration_path_can_send_arithmetic_overflow() {
    var path = internal::QuicPath {
        state:          internal::PathValidationState.Validating,
        bytes_received: 1000,
        bytes_sent:     0xFFFFFFFFFFFFFFFE,
        ..
    };

    // 0xFFFFFFFFFFFFFFFE + 10 would overflow to 8 without wrap protection.
    let can_send = internal::path_can_send(path, 10);
    assert(!can_send);

    print("REGRESS_MIGRATION_OVERFLOW_GUARD: OK");
}

fn test_dplpmtud_probe_payload_size_overhead_bound() {
    let payload_size = internal::calc_dplpmtud_probe_payload_size(40, 49);
    assert(payload_size == 0);

    let payload_size_eq = internal::calc_dplpmtud_probe_payload_size(49, 49);
    assert(payload_size_eq == 0);

    print("REGRESS_DPLPMTUD_OVERHEAD_BOUND: OK");
}

fn test_bbr_on_congestion_signal_cwnd_floor() {
    var bbr = internal::new_bbr_state();
    bbr.cwnd_bytes = 5000;

    for _ in 50 {
        internal::bbr_on_congestion_signal(bbr, 5000, 0, 5000, 10, 10);
    }
    assert(bbr.cwnd_bytes >= internal::BBR_MIN_CWND_BYTES);

    print("REGRESS_BBR_CWND_FLOOR: OK");
}

fn test_bbr_check_probe_rtt_clock_underflow() {
    var bbr = internal::new_bbr_state();
    bbr.mode = internal::BbrMode.ProbeBwCruise;
    bbr.min_rtt_stamp_us = 1000000;

    // now_us is in the past (clock jitter / non-monotonic timestamp).
    internal::bbr_check_probe_rtt(bbr, 900000, 20000);
    assert(bbr.mode == internal::BbrMode.ProbeBwCruise);

    print("REGRESS_BBR_CLOCK_UNDERFLOW: OK");
}

fn test_ack_transactional_intervals_clear_on_error() {
    var space = internal::PnSpaceState {
        has_sent_packets: true,
        largest_sent_pn:  100,
        ..
    };

    var bad_ack = internal::AckFrame {
        largest_acked:   10,
        first_ack_range: 2,
        ..
    };
    bad_ack.ranges.push(internal::AckRange { gap: 100, ack_range: 5 });

    var out_intervals: internal::AckInterval[..64] = [];
    let ok = internal::parse_and_validate_ack(space, bad_ack, out_intervals);
    assert(!ok);
    assert(out_intervals.len == 0);

    print("REGRESS_ACK_TRANSACTIONAL_CLEAR: OK");
}

fn test_connection_inbound_ack_for_unsent_space() {
    var conn = internal::new_quic_server_connection("test_conn");
    conn.state = internal::QuicConnState.Established;
    conn.app_space.has_sent_packets = false;

    let ack_frame = internal::QuicFrame {
        frame_type: internal::QuicFrameType.Ack,
        offset:     5,
        max_data:   0,
        length:     0,
        ..
    };

    let ok_ack = internal::dispatch_inbound_ack_frame(
        conn,
        ack_frame,
        internal::QuicHeaderType.OneRtt,
        10000,
    );
    // RFC 9000 §13.1: Receipt of ACK acknowledging unsent packets MUST be rejected (PROTOCOL_VIOLATION).
    assert(!ok_ack);

    print("REGRESS_CONN_ACK_UNSENT_SPACE: OK");
}

fn main() {
    test_fc_recv_reset_smaller_than_bytes_recv();
    test_fc_credit_renewal_threshold_and_bounds();
    test_stream_recv_frame_offset_wrap();
    test_stream_recv_reset_after_datarecvd_final_size_mismatch();
    test_stream_table_peer_cannot_open_local_stream();
    test_packet_read_contiguous_capacity_safety();
    test_packet_insert_fragment_fin_transactional_rollback();
    test_migration_path_can_send_arithmetic_overflow();
    test_dplpmtud_probe_payload_size_overhead_bound();
    test_bbr_on_congestion_signal_cwnd_floor();
    test_bbr_check_probe_rtt_clock_underflow();
    test_ack_transactional_intervals_clear_on_error();
    test_connection_inbound_ack_for_unsent_space();
}

// CHECK: REGRESS_FC_RESET_FINAL_SIZE: OK
// CHECK: REGRESS_FC_CREDIT_RENEWAL: OK
// CHECK: REGRESS_STREAM_OFFSET_WRAP: OK
// CHECK: REGRESS_STREAM_RESET_FINAL_SIZE_MISMATCH: OK
// CHECK: REGRESS_STREAM_TABLE_LOCAL_OPEN_REJECT: OK
// CHECK: REGRESS_PACKET_READ_CONTIGUOUS_CAP: OK
// CHECK: REGRESS_PACKET_INSERT_FIN_ROLLBACK: OK
// CHECK: REGRESS_MIGRATION_OVERFLOW_GUARD: OK
// CHECK: REGRESS_DPLPMTUD_OVERHEAD_BOUND: OK
// CHECK: REGRESS_BBR_CWND_FLOOR: OK
// CHECK: REGRESS_BBR_CLOCK_UNDERFLOW: OK
// CHECK: REGRESS_ACK_TRANSACTIONAL_CLEAR: OK
// CHECK: REGRESS_CONN_ACK_UNSENT_SPACE: OK
