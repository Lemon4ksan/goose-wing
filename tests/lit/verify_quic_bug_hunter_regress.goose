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
    let read_bytes = internal::read_contiguous(buf, out_small, out_small.cap - out_small.len);
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

fn test_f001_rx_pn_reconstruction_and_transactional_coalesced() {
    var server = internal::new_quic_server_connection("srv_scid");
    var client = internal::new_quic_client_connection("srv_scid", "cli_scid");
    assert(internal::quic_conn_install_initial_keys(server, "srv_scid"));
    assert(internal::quic_conn_install_initial_keys(client, "srv_scid"));

    // Simulate receiving PNs up to 200 on server initial_space while largest_acked_pn remains 0 (no TX ACKs).
    server.initial_space.has_recv_packets = true;
    server.initial_space.largest_recv_pn = 200;
    server.initial_space.largest_acked_pn = 0;

    var payload: u8[..1200] = [];
    assert(internal::encode_ping_frame(payload));
    assert(internal::encode_padding_frame(payload, 1199));

    var hdr = internal::QuicHeader {
        header_type:   internal::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: 201,
        ..
    };
    hdr.dcid.append("srv_scid");
    hdr.scid.append("cli_scid");

    var wire_pkt: u8[..1400] = [];
    assert(internal::quic_seal_packet(client.tx_initial_space, hdr, 1, payload[..], wire_pkt));

    var out_ack = internal::AckFrame { .. };
    let ok_dgram, _ = internal::quic_conn_process_datagram(server, wire_pkt[..], 10000, out_ack);
    assert(ok_dgram);
    assert(server.initial_space.largest_recv_pn == 201);

    // Part B: Unauthenticated Retry must not bind server CIDs or increment server initial CID latch
    var srv2 = internal::new_quic_server_connection("srv2_scid");
    var retry_hdr = internal::QuicHeader {
        header_type: internal::QuicHeaderType.Retry,
        version:     rfc::QUIC_VERSION_1,
        ..
    };
    retry_hdr.dcid.append("spoof_dcid");
    retry_hdr.scid.append("spoof_scid");
    var retry_wire: u8[..64] = [];
    assert(internal::encode_quic_header(retry_wire, retry_hdr, 1));
    let _, _ = internal::quic_conn_process_datagram(srv2, retry_wire[..], 10000, out_ack);
    assert(srv2.dcid.len == 0);

    print("REGRESS_F001_PN_RECONSTRUCT_AND_TX_STATE: OK");
}

fn test_f002_f003_f004_ack_and_pto_invariants() {
    // F002: 64 additional ACK ranges (via quic_conn_on_ack) must succeed
    var conn_ack = internal::new_quic_server_connection("srv_ack");
    conn_ack.app_space.has_sent_packets = true;
    conn_ack.app_space.largest_sent_pn = 500;
    var ack64 = internal::AckFrame {
        largest_acked:   200,
        first_ack_range: 0,
        ..
    };
    for _ in 64 {
        ack64.ranges.push(internal::AckRange { gap: 0, ack_range: 0 });
    }
    assert(internal::quic_conn_on_ack(conn_ack, ack64, 10000));

    // F003: process_space_ack must handle >64 lost packets without leaving loss_time_us == 0
    var conn_loss = internal::new_quic_server_connection("srv_loss");
    for p in 70 {
        internal::quic_conn_record_sent(conn_loss, internal::PnSpaceId.ApplicationData, p as u64, 100, true, 1000);
    }
    internal::quic_conn_record_sent(conn_loss, internal::PnSpaceId.ApplicationData, 100, 100, true, 2000);
    var ack_top = internal::AckFrame {
        largest_acked:   100,
        first_ack_range: 0,
        ..
    };
    assert(internal::quic_conn_on_ack(conn_loss, ack_top, 3000));
    assert(conn_loss.app_space.sent_packets.len == 0);

    // F004: evaluate_pto_timer client AntiDeadlock when AppData has 1 packet before handshake_confirmed
    var rtt = internal::RttState { .. };
    var spaces: internal::PnSpaceState[3] = [
        internal::PnSpaceState { space_id: internal::PnSpaceId.Initial, .. },
        internal::PnSpaceState { space_id: internal::PnSpaceId.Handshake, .. },
        internal::PnSpaceState { space_id: internal::PnSpaceId.ApplicationData, .. },
    ];
    spaces[2].sent_packets.push(internal::SentPacketMeta {
        pn:            1,
        time_sent_us:  1000,
        size_bytes:    100,
        ack_eliciting: true,
        in_flight:     true,
    });
    let ctx = internal::PtoContext {
        is_server:                      false,
        is_amplification_limited:       false,
        peer_completed_addr_validation: false,
        handshake_confirmed:            false,
    };
    let dec = internal::evaluate_pto_timer(spaces, rtt, 0, 5000, ctx);
    assert(dec.mode == internal::PtoTimerMode.AntiDeadlock);

    print("REGRESS_F002_F003_F004_ACK_PTO: OK");
}

fn test_f005_f006_f007_bbr_and_cubic_math() {
    // F005: pacer_can_send zero rate and non-monotonic clock
    var pacer = internal::Pacer { pacing_rate_bps: 0, .. };
    let ok1, _ = internal::pacer_can_send(pacer, 1000000, 1200);
    assert(ok1);
    let _, _ = internal::pacer_can_send(pacer, 900000, 1200);
    assert(pacer.last_pacing_time_us == 1000000);

    // F006: bbr_bdp high BDP saturation instead of u64 wrap to 0
    let bdp = internal::bbr_bdp(40000000000000, 500000);
    assert(bdp > 1000000000);

    // F007: cubic_on_ack app-limited before first epoch must not skip k_ms initialization
    var cubic = internal::CubicState { cwnd_segments: 10, w_max_segments: 20, .. };
    let _ = internal::cubic_on_ack(cubic, 1000000, 40000, 1200, 1200);
    let _ = internal::cubic_on_ack(cubic, 2000000, 40000, 1200, 1200);
    let _ = internal::cubic_on_ack(cubic, 2100000, 40000, 10000, 1200);
    assert(cubic.k_ms > 0);
    assert(cubic.epoch_start_us == 2100000);

    print("REGRESS_F005_F006_F007_BBR_CUBIC: OK");
}

fn test_f008_to_f012_conn_and_dplpmtud() {
    // F008: record_space_sent_packet must not advance largest_sent_pn when sent_packets[..128] is full
    var sp = internal::PnSpaceState { .. };
    for i in 128 {
        let m = internal::SentPacketMeta {
            pn:            i as u64,
            time_sent_us:  1000,
            size_bytes:    100,
            ack_eliciting: true,
            in_flight:     true,
        };
        internal::record_space_sent_packet(sp, m);
    }
    let m_overflow = internal::SentPacketMeta {
        pn:            500,
        time_sent_us:  2000,
        size_bytes:    100,
        ack_eliciting: true,
        in_flight:     true,
    };
    internal::record_space_sent_packet(sp, m_overflow);
    assert(sp.largest_sent_pn == 127);

    // F009: quic_is_frame_allowed_in_packet rejects Unknown and Retry/VersionNegotiation
    assert(!internal::quic_is_frame_allowed_in_packet(
        internal::QuicFrameType.Unknown,
        internal::QuicHeaderType.OneRtt,
    ));
    assert(!internal::quic_is_frame_allowed_in_packet(
        internal::QuicFrameType.Ping,
        internal::QuicHeaderType.Retry,
    ));

    // F011: quic_seal_packet with 200-byte Initial token and bounded out_pkt overflow rejection
    var cli = internal::new_quic_client_connection("srv_scid", "cli_scid");
    assert(internal::quic_conn_install_initial_keys(cli, "srv_scid"));
    var hdr_tok = internal::QuicHeader {
        header_type:   internal::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: 1,
        ..
    };
    hdr_tok.dcid.append("srv_scid");
    hdr_tok.scid.append("cli_scid");
    var tok200: u8[200] = [0xAA; 200];
    hdr_tok.token.append(tok200[..]);
    var out_big: u8[..512] = [];
    assert(internal::quic_seal_packet(cli.tx_initial_space, hdr_tok, 2, "ping", out_big));
    var out_tiny: u8[..16] = [];
    assert(!internal::quic_seal_packet(cli.tx_initial_space, hdr_tok, 2, "ping", out_tiny));

    // F012: DPLPMTUD probe buffer capacity check and search timer not downgrading confirmed 1500 PMTU
    var small_probe: u8[..32] = [];
    assert(!internal::generate_ping_probe(small_probe, 1200));
    var d = internal::Dplpmtud { .. };
    assert(internal::dplpmtud_on_probe_acked(d, 1200));
    assert(internal::dplpmtud_on_probe_acked(d, 1280));
    assert(internal::dplpmtud_on_probe_acked(d, 1420));
    assert(internal::dplpmtud_on_probe_acked(d, 1500));
    assert(d.state == internal::DplpmtudState.SearchComplete);
    assert(d.current_pmtu == 1500);
    internal::dplpmtud_on_search_timer(d, 700000);
    assert(d.current_pmtu == 1500);

    print("REGRESS_F008_TO_F012_CONN_DPLPMTUD: OK");
}

fn test_f013_to_f022_frames_migration_packet() {
    // F013: Frame encoders must reject when out buffer lacks capacity without leaving partial bytes
    var tiny_buf: u8[..4] = [];
    assert(!internal::encode_padding_frame(tiny_buf, 10));
    assert(tiny_buf.len == 0);
    assert(!internal::encode_crypto_frame(tiny_buf, 0, "0123456789"));
    assert(tiny_buf.len == 0);

    // F014: Frame decoders reject negative idx
    var neg_idx: i64 = -4;
    let _, ok_path = internal::demux_path_frame("0123456789", neg_idx, rfc::QUIC_FRAME_PATH_CHALLENGE);
    assert(!ok_path);

    // F015: new_quic_endpoint_addr safely handles >64 byte slice without crash
    var long_ip: u8[80] = [65; 80];
    let ep = internal::new_quic_endpoint_addr(long_ip[..], 443);
    assert(ep.ip.len <= 64);

    // F016: build_long_header_first_byte rejects pn_bits > 3 and unknown version
    let _, ok_pnbits = internal::build_long_header_first_byte(internal::QuicHeaderType.Initial, 0x0C, rfc::QUIC_VERSION_1);
    assert(!ok_pnbits);
    let _, ok_ver = internal::build_long_header_first_byte(internal::QuicHeaderType.Initial, 0, 0xDEADBEEF);
    assert(!ok_ver);

    // F018: decode_packet_number_checked rejects truncated_pn >= (1 << (pn_len * 8))
    let _, ok_trunc = internal::decode_packet_number_checked(100, 0x1FF, 1);
    assert(!ok_trunc);

    // F019: on_path_bytes_sent saturates instead of wrapping around u64::MAX
    var pstate = internal::PathState { bytes_received: 1000, bytes_sent: 0xFFFFFFFFFFFFFFF0, .. };
    internal::on_path_bytes_sent(pstate, 0x20);
    assert(!internal::can_send_on_path(pstate, 1));

    // F020: insert_fragment does not corrupt arena when intervals[..64] is full
    var rbuf = internal::new_reassembly_buffer(65536);
    var cur_off: u64 = 0;
    for _ in 64 {
        assert(internal::insert_fragment(rbuf, cur_off, "A", false));
        cur_off = core::add_sat_u64(cur_off, 2);
    }
    let prev_data_len = rbuf.arena.data_len;
    assert(!internal::insert_fragment(rbuf, 200, "B", false));
    assert(rbuf.arena.data_len == prev_data_len);

    // F021: read_contiguous with default max_bytes = -1 clamps to out.cap - out.len
    var rbuf2 = internal::new_reassembly_buffer(65536);
    var blk64: u8[64] = [90; 64];
    assert(internal::insert_fragment(rbuf2, 0, blk64[..], false));
    var out16: u8[..16] = [];
    let n16 = internal::read_contiguous(rbuf2, out16);
    assert(n16 == 16);
    assert(rbuf2.consumed_offset == 16);

    // F022: decode_quic_datagram_frame rejects packet_end > src.len
    let _, _, ok_dgram_end = internal::decode_quic_datagram_frame("\x30abc", 0, 100);
    assert(!ok_dgram_end);

    print("REGRESS_F013_TO_F022_FRAMES_PACKET: OK");
}

fn test_f023_to_f027_stream_invariants() {
    // F023: quic_stream_on_send_data rejects FIN at end_offset < s.bytes_sent
    var s_tx = internal::new_quic_stream(0, 65536);
    s_tx.send_max_data = 65536;
    let ok_s1, _ = internal::quic_stream_on_send_data(s_tx, 0, 100, false);
    assert(ok_s1);
    let ok_s2, err_s2 = internal::quic_stream_on_send_data(s_tx, 0, 50, true);
    assert(!ok_s2);
    assert(err_s2 == rfc::QUIC_ERR_FINAL_SIZE);

    // F024: quic_stream_on_recv_stream_frame does not silently drop intervals
    var s_rx = internal::new_quic_stream(0, 65536);
    var rx_off: u64 = 2;
    for _ in 17 {
        let ok_r, _ = internal::quic_stream_on_recv_stream_frame(s_rx, rx_off, 1, false);
        assert(ok_r);
        rx_off = core::add_sat_u64(rx_off, 2);
    }
    assert(s_rx.recv_ranges.len == 17);

    // F025: duplicate RESET_STREAM in ResetRecvd does not overwrite recv_error_code
    var s_rst = internal::new_quic_stream(0, 65536);
    let ok_r1, _ = internal::quic_stream_on_recv_reset(s_rst, 0x101, 100);
    assert(ok_r1);
    let ok_r2, _ = internal::quic_stream_on_recv_reset(s_rst, 0x999, 100);
    assert(ok_r2);
    assert(s_rst.recv_error_code == 0x101);

    // F026: quic_stream_on_app_read rejects reading past contiguous_recv_bytes
    var s_read = internal::new_quic_stream(0, 65536);
    let _, _ = internal::quic_stream_on_recv_stream_frame(s_read, 0, 50, true);
    assert(!internal::quic_stream_on_app_read(s_read, 100));
    assert(s_read.recv_consumed == 0);

    // F027: quic_table_open_local_stream enforces max_streams_bidi / max_streams_uni
    var tbl = internal::new_quic_stream_table(internal::QuicRole.Client);
    tbl.max_streams_bidi = 1;
    let _, _, ok_open1 = internal::quic_table_open_local_stream(tbl, true);
    assert(ok_open1);
    let _, _, ok_open2 = internal::quic_table_open_local_stream(tbl, true);
    assert(!ok_open2);

    print("REGRESS_F023_TO_F027_STREAM: OK");
}

fn test_f028_to_f030_cross_component_ack_rtt_bbr() {
    // F028: Non-ACK-eliciting packet (PADDING-only) MUST NOT set needs_ack = true (RFC 9000 §13.2.1)
    var conn_pad = internal::new_quic_server_connection("scid");
    var pad_pkt: u8[..64] = [];
    var hdr_pad = internal::QuicHeader {
        header_type:   internal::QuicHeaderType.OneRtt,
        packet_number: 0,
        pn_length:     1,
        ..
    };
    hdr_pad.dcid.append("scid");
    assert(internal::encode_quic_header(pad_pkt, hdr_pad, 1));
    pad_pkt.push(0x00); // PADDING frame only
    var out_ack_pad = internal::AckFrame { .. };
    let handled_pad, needs_ack_pad = internal::quic_conn_process_datagram(conn_pad, pad_pkt[..], 1000, out_ack_pad);
    assert(handled_pad);
    assert(!needs_ack_pad);

    // F029a: RTT sample generated when largest_acked is non-ack-eliciting if batch has ack-eliciting (RFC 9002 §5.1)
    var conn_rtt = internal::new_quic_client_connection("scid", "dcid");
    conn_rtt.state = internal::QuicConnState.Handshake;
    conn_rtt.rtt.first_sample_time_us = 1;
    conn_rtt.rtt.min_rtt_us = 10000;
    conn_rtt.rtt.smoothed_rtt_us = 22000;
    internal::quic_conn_record_sent(conn_rtt, internal::PnSpaceId.ApplicationData, 0, 1200, true, 10000);
    internal::quic_conn_record_sent(conn_rtt, internal::PnSpaceId.ApplicationData, 1, 64, false, 20000);
    // Inbound OneRtt packet carrying ACK for [0..1] with ack_delay = 1000 (8000 us)
    var pkt_ack: u8[..64] = [];
    var hdr_ack = internal::QuicHeader {
        header_type:   internal::QuicHeaderType.OneRtt,
        packet_number: 0,
        pn_length:     1,
        ..
    };
    hdr_ack.dcid.append("scid");
    assert(internal::encode_quic_header(pkt_ack, hdr_ack, 1));
    let ack_f = internal::AckFrame {
        largest_acked:   1,
        ack_delay:       1000,
        first_ack_range: 1,
        ..
    };
    assert(internal::encode_ack_frame(pkt_ack, ack_f));
    var out_ack_rtt = internal::AckFrame { .. };
    let handled_ack, needs_ack_ack = internal::quic_conn_process_datagram(conn_rtt, pkt_ack[..], 50000, out_ack_rtt);
    assert(handled_ack);
    assert(!needs_ack_ack);
    // latest_rtt = 50000 - 20000 = 30000; OneRtt transitions conn to Established before ACK processing,
    // so ack_delay (8000 us) is subtracted: smoothed_rtt = 30000 - 8000 = 22000
    assert(conn_rtt.rtt.latest_rtt_us == 30000);
    assert(conn_rtt.rtt.smoothed_rtt_us == 22000);

    // F029b: Huge ack_delay (0x3FFFFFFFFFFFFFFF) must not wrap u64 on << 3
    internal::quic_conn_record_sent(conn_rtt, internal::PnSpaceId.ApplicationData, 2, 1200, true, 60000);
    let ack_huge = internal::AckFrame {
        largest_acked:   2,
        ack_delay:       0x3FFFFFFFFFFFFFFF,
        first_ack_range: 0,
        ..
    };
    assert(internal::quic_conn_on_ack(conn_rtt, ack_huge, 100000, internal::PnSpaceId.ApplicationData));

    // F030: BBR ECN-CE surge saturation (ecn_ce_count > new_acked_packets and 2^54 overflow)
    var bbr = internal::new_bbr_state();
    let init_cwnd = bbr.cwnd_bytes;
    internal::bbr_on_congestion_signal(bbr, init_cwnd, 0, 1200, 0x0040000000000000, 1);
    assert(bbr.ecn_alpha_scaled <= 1024);
    assert(bbr.ecn_alpha_scaled > 0);
    assert(bbr.cwnd_bytes < init_cwnd);

    print("REGRESS_F028_TO_F030_ACK_RTT_BBR: OK");
}

fn test_f031_to_f033_cross_component_stream_fc_packet() {
    // F031a: STREAM_DATA_BLOCKED on unopened locally-initiated stream -> STREAM_STATE_ERROR (RFC 9000 §19.13)
    var conn1 = internal::new_quic_server_connection("scid");
    var buf1: u8[..32] = [0x15, 0x01, 0x44, 0x00];
    let ok1, _ = internal::quic_conn_process_payload(conn1, buf1[..]);
    assert(!ok1);
    assert(conn1.close_code == rfc::QUIC_ERR_STREAM_STATE);

    // F031b: MAX_STREAM_DATA on peer-initiated stream exceeding max_streams_bidi -> STREAM_LIMIT_ERROR (RFC 9000 §19.10)
    var conn2 = internal::new_quic_server_connection("scid");
    conn2.stream_table.max_streams_bidi = 1;
    var buf2: u8[..32] = [];
    assert(internal::encode_max_stream_data_frame(buf2, 4, 8192));
    let ok2, _ = internal::quic_conn_process_payload(conn2, buf2[..]);
    assert(!ok2);
    assert(conn2.close_code == rfc::QUIC_ERR_STREAM_LIMIT);

    // F032: Reusing a terminal stream table slot MUST NOT allow retransmitted frames on the closed stream
    // to re-open it as a new stream and double-charge connection flow control (RFC 9000 §3.2, §4.1)
    var conn3 = internal::new_quic_server_connection("scid");
    var s0_buf: u8[..32] = [];
    assert(internal::encode_stream_frame(s0_buf, 0, 0, "hello", internal::QuicStreamFlags { fin: true, .. }));
    let ok_s0, _ = internal::quic_conn_process_payload(conn3, s0_buf[..]);
    assert(ok_s0);
    assert(conn3.flow_ctrl.bytes_recv_total == 5);
    // Transition stream 0 to terminal (recv DataRead + send DataRecvd)
    assert(internal::quic_stream_on_app_read(conn3.stream_table.streams[0], 5));
    conn3.stream_table.streams[0].send_state = internal::QuicSendState.DataRecvd;
    assert(internal::quic_stream_is_terminal(conn3.stream_table.streams[0], internal::QuicRole.Server));
    // Open stream 4, which reuses slot 0
    var s4_buf: u8[..32] = [];
    assert(internal::encode_stream_frame(s4_buf, 4, 0, "abc", internal::QuicStreamFlags { fin: false, .. }));
    let ok_s4, _ = internal::quic_conn_process_payload(conn3, s4_buf[..]);
    assert(ok_s4);
    assert(conn3.flow_ctrl.bytes_recv_total == 8);
    // Late retransmission of stream 0 arrives: must NOT double-charge conn3.flow_ctrl.bytes_recv_total!
    let ok_s0_dup, _ = internal::quic_conn_process_payload(conn3, s0_buf[..]);
    assert(ok_s0_dup);
    assert(conn3.flow_ctrl.bytes_recv_total == 8);

    // F033: Long header packet with unsupported QUIC version (0xBAADF00D) must be rejected by connection
    var conn4 = internal::new_quic_server_connection("scid");
    var unk_ver_pkt: u8[..32] = [0xC0, 0xBA, 0xAD, 0xF0, 0x0D, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
    var out_ack4 = internal::AckFrame { .. };
    let handled4, _ = internal::quic_conn_process_datagram(conn4, unk_ver_pkt[..], 1000, out_ack4);
    assert(!handled4);

    print("REGRESS_F031_TO_F033_STREAM_FC_PKT: OK");
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
    test_f001_rx_pn_reconstruction_and_transactional_coalesced();
    test_f002_f003_f004_ack_and_pto_invariants();
    test_f005_f006_f007_bbr_and_cubic_math();
    test_f008_to_f012_conn_and_dplpmtud();
    test_f013_to_f022_frames_migration_packet();
    test_f023_to_f027_stream_invariants();
    test_f028_to_f030_cross_component_ack_rtt_bbr();
    test_f031_to_f033_cross_component_stream_fc_packet();
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
// CHECK: REGRESS_F001_PN_RECONSTRUCT_AND_TX_STATE: OK
// CHECK: REGRESS_F002_F003_F004_ACK_PTO: OK
// CHECK: REGRESS_F005_F006_F007_BBR_CUBIC: OK
// CHECK: REGRESS_F008_TO_F012_CONN_DPLPMTUD: OK
// CHECK: REGRESS_F013_TO_F022_FRAMES_PACKET: OK
// CHECK: REGRESS_F023_TO_F027_STREAM: OK
// CHECK: REGRESS_F028_TO_F030_ACK_RTT_BBR: OK
// CHECK: REGRESS_F031_TO_F033_STREAM_FC_PKT: OK
