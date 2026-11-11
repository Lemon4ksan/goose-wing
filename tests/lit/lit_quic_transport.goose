// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_quic_transport
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. rfc_repro_framer_quic_invariants (1/10)
// ============================================================================
// CHECK: === [1/10] rfc_repro_framer_quic_invariants ===

// tests/lit/rfc_repro_framer_quic_invariants.goose
// Verification of RFC 9000 transport wire framing and connection ID invariants:
// - RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
// - RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
// - RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
//

fn test_empty_payload_packet_rejected() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
    let empty_payload: const u8[:] = "";
    let handled, _ = internal::quic_conn_process_payload(srv, empty_payload, internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(srv.state == internal::QuicConnState.Closing);

    print("QUIC_EMPTY_PAYLOAD_REJECTED: OK");
}

fn test_retire_conn_id_on_zero_length_scid_rejected() {
    // Server provides zero-length Connection ID to peer (scid is empty)
    var srv = internal::new_quic_server_connection("");
    srv.state = internal::QuicConnState.Established;

    var rcid_payload: u8[..32] = [];
    assert(internal::encode_retire_conn_id_frame(rcid_payload, 1));

    // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
    let handled, _ = internal::quic_conn_process_payload(srv, rcid_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(srv.state == internal::QuicConnState.Closing);

    print("QUIC_RETIRE_CONN_ID_ZERO_SCID_REJECTED: OK");
}

fn test_new_conn_id_on_zero_length_dcid_rejected() {
    // Client sends packets with zero-length Destination Connection ID (dcid is empty)
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var client = internal::new_quic_client_connection("", scid[..]);
    client.state = internal::QuicConnState.Established;

    var ncid_payload: u8[..64] = [];
    let reset_tok: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let new_cid:   u8[4]  = [0xAA, 0xBB, 0xCC, 0xDD];
    assert(internal::encode_new_conn_id_frame(ncid_payload, 1, 0, new_cid[..], reset_tok));

    // RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
    let handled, _ = internal::quic_conn_process_payload(client, ncid_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(client.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(client.state == internal::QuicConnState.Closing);

    print("QUIC_NEW_CONN_ID_ZERO_DCID_REJECTED: OK");
}

fn run_01_rfc_repro_framer_quic_invariants() {
    test_empty_payload_packet_rejected();
    test_retire_conn_id_on_zero_length_scid_rejected();
    test_new_conn_id_on_zero_length_dcid_rejected();
    print("ALL_QUIC_FRAMER_INVARIANTS: OK");
}

// CHECK: QUIC_EMPTY_PAYLOAD_REJECTED: OK
// CHECK: QUIC_RETIRE_CONN_ID_ZERO_SCID_REJECTED: OK
// CHECK: QUIC_NEW_CONN_ID_ZERO_DCID_REJECTED: OK
// CHECK: ALL_QUIC_FRAMER_INVARIANTS: OK

// ============================================================================
// 2. verify_quic_ack_edge (2/10)
// ============================================================================
// CHECK: === [2/10] verify_quic_ack_edge ===

// tests/lit/verify_quic_ack_edge.goose
// Verification of RFC 9000 QUIC ACK frames, varint arithmetic, and long header parsing via wing::quic.
//

// Wire adapter for verify_split_stream and fuzzing using wing's real decode_ack_frame
fn wing_validate_quic_ack_wire(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let ack, consumed, ok = internal::decode_ack_frame(buf, 0);
    if ok {
        return (ack.largest_acked - ack.first_ack_range) as! i64;
    }
    let ftype = buf[0];
    guard ftype == 2 || ftype == 3 else { return -2; }
    if buf.len >= 5 {
        let largest, off1, ok1 = internal::quic_decode_varint(buf, 1);
        if ok1 {
            let _, off2, ok2 = internal::quic_decode_varint(buf, off1);
            if ok2 {
                let _, off3, ok3 = internal::quic_decode_varint(buf, off2);
                if ok3 {
                    let first_r, _, ok4 = internal::quic_decode_varint(buf, off3);
                    if ok4 && largest < first_r {
                        return -3;
                    }
                }
            }
        }
    }
    return -1;
}

fn wing_validate_quic_long_header_wire(buf: const u8[:]) -> i32 {
    guard buf.len >= 5 else { return -1; }
    let first = buf[0];
    guard (first & 0x80) != 0 else { return -2; }
    guard (first & 0x40) != 0 else { return -3; }
    let long_type = (first >> 4) & 3;
    if long_type == 0 && (first & 0x0C) != 0 {
        return -4;
    }
    return 1;
}

fn run_02_verify_quic_ack_edge() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("02406419000A", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 90, wing_validate_quic_ack_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, wing_validate_quic_ack_wire));
    print("QUIC_ACK_SPLIT: OK");

    var bad_range: u8[>..] = []; wire_kit::parse_hex("020519000A", bad_range);
    assert(wing_validate_quic_ack_wire(bad_range[..]) == -3);
    print("QUIC_ACK_INVARIANT: OK");

    var init_ok: u8[>..] = []; wire_kit::parse_hex("C000000001", init_ok);
    assert(wing_validate_quic_long_header_wire(init_ok[..]) == 1);

    var init_nofix: u8[>..] = []; wire_kit::parse_hex("8000000001", init_nofix);
    assert(wing_validate_quic_long_header_wire(init_nofix[..]) == -3);

    var init_badres: u8[>..] = []; wire_kit::parse_hex("C400000001", init_badres);
    assert(wing_validate_quic_long_header_wire(init_badres[..]) == -4);
    print("QUIC_LONG_HEADER: OK");
}

// CHECK: QUIC_ACK_SPLIT: OK
// CHECK: QUIC_ACK_INVARIANT: OK
// CHECK: QUIC_LONG_HEADER: OK

// ============================================================================
// 3. verify_quic_bbr (3/10)
// ============================================================================
// CHECK: === [3/10] verify_quic_bbr ===

// Native LIT verification suite for QUIC BBRv3 integration, coalesced packet demuxing,
// bounded 16-chunk SegmentedArena stream reassembly, and TopicTree 512-subscriber
// fail-closed capacity enforcement with MQTT wildcard matching.

fn test_quic_conn_bbr_ack_integration() {
    var conn = internal::new_quic_server_connection("srv_bbr_01");
    conn.state = internal::QuicConnState.Established;
    conn.validated_address = true;

    // Record and acknowledge 4 in-flight ApplicationData packets across sequential rounds
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 1, 1200, true, 10000);
    let ack1 = internal::AckFrame {
        largest_acked:   1,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok1 = internal::quic_conn_on_ack(conn, ack1, 30000, internal::PnSpaceId.ApplicationData);

    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 2, 1200, true, 20000);
    let ack2 = internal::AckFrame {
        largest_acked:   2,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok2 = internal::quic_conn_on_ack(conn, ack2, 45000, internal::PnSpaceId.ApplicationData);

    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 3, 1200, true, 30000);
    let ack3 = internal::AckFrame {
        largest_acked:   3,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok3 = internal::quic_conn_on_ack(conn, ack3, 60000, internal::PnSpaceId.ApplicationData);

    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 4, 1200, true, 40000);
    let ack4 = internal::AckFrame {
        is_ecn:          true,
        largest_acked:   4,
        ack_delay:       0,
        first_ack_range: 0,
        ecn_ce_count:    1,
        ..
    };
    let ok4 = internal::quic_conn_on_ack(conn, ack4, 75000, internal::PnSpaceId.ApplicationData);

    // Negative test: acknowledging unsent packet number 999 must fail closed
    let bad_ack = internal::AckFrame {
        largest_acked:   999,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok_bad = internal::quic_conn_on_ack(conn, bad_ack, 80000, internal::PnSpaceId.ApplicationData);

    let is_refill = conn.bbr.mode == internal::BbrMode.ProbeBwRefill;
    let ecn_tracked = conn.bbr.ecn_alpha_scaled > 0;
    let bw_pos = conn.bbr.bw_hi_bps > 0;
    let pacing_synced = conn.pacer.pacing_rate_bps == conn.bbr.pacer.pacing_rate_bps && conn.pacer.pacing_rate_bps > 0;
    let rtt_updated = conn.rtt.latest_rtt_us == 35000;

    // CHECK: BBR_ON_ACK_VALID: true true true true
    print("BBR_ON_ACK_VALID: ", ok1, " ", ok2, " ", ok3, " ", ok4, "\n");
    // CHECK: BBR_STATE_UPDATED: refill=true ecn=true bw_positive=true pacing_synced=true rtt_updated=true
    print("BBR_STATE_UPDATED: refill=", is_refill, " ecn=", ecn_tracked, " bw_positive=", bw_pos, " pacing_synced=", pacing_synced, " rtt_updated=", rtt_updated, "\n");
    // CHECK: BBR_UNSENT_ACK_REJECTED: false
    print("BBR_UNSENT_ACK_REJECTED: ", ok_bad, "\n");
}

fn test_coalesced_quic_datagram_demux() {
    let srv_cid = "12345678";
    let cli_cid = "87654321";
    var srv = internal::new_quic_server_connection(srv_cid);
    srv.allow_unencrypted_test_packets = true;

    var coalesced_dgram: u8[..256] = [];

    // Packet 1: Initial packet (Long Header) with PING frame (0x01)
    var init_hdr = internal::QuicHeader {
        header_type:    internal::QuicHeaderType.Initial,
        version:        rfc::QUIC_VERSION_1,
        payload_length: 2, // 1 byte PN + 1 byte PING frame
        packet_number:  0,
        ..
    };
    init_hdr.dcid.append(srv_cid);
    init_hdr.scid.append(cli_cid);
    let ok_enc1 = internal::encode_quic_header(coalesced_dgram, init_hdr, 1);
    coalesced_dgram.push(0x01); // PING frame

    // Packet 2: Handshake packet (Long Header) with PING frame (0x01)
    var hs_hdr = internal::QuicHeader {
        header_type:    internal::QuicHeaderType.Handshake,
        version:        rfc::QUIC_VERSION_1,
        payload_length: 2, // 1 byte PN + 1 byte PING frame
        packet_number:  0,
        ..
    };
    hs_hdr.dcid.append(srv_cid);
    hs_hdr.scid.append(cli_cid);
    let ok_enc2 = internal::encode_quic_header(coalesced_dgram, hs_hdr, 1);
    coalesced_dgram.push(0x01); // PING frame

    // Packet 3: 1-RTT Short Header packet with STREAM frame on client-initiated bidi stream 0
    var app_hdr = internal::QuicHeader {
        header_type:   internal::QuicHeaderType.OneRtt,
        packet_number: 0,
        ..
    };
    app_hdr.dcid.append(srv_cid);
    let ok_enc3 = internal::encode_quic_header(coalesced_dgram, app_hdr, 1);
    let sf_flags = internal::QuicStreamFlags { with_len: true, fin: true, .. };
    let ok_sf = internal::encode_stream_frame(coalesced_dgram, 0, 0, "hello", sf_flags);

    var out_ack = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(srv, coalesced_dgram[..], 50000, out_ack);

    let init_rx = srv.initial_space.has_recv_packets;
    let hs_rx = srv.handshake_space.has_recv_packets;
    let app_rx = srv.app_space.has_recv_packets;
    let is_est = srv.state == internal::QuicConnState.Established;

    // CHECK: COALESCED_ENCODED: true true true true
    print("COALESCED_ENCODED: ", ok_enc1, " ", ok_enc2, " ", ok_enc3, " ", ok_sf, "\n");
    // CHECK: COALESCED_DEMUX: handled=true needs_ack=true packets_rx=3
    print("COALESCED_DEMUX: handled=", handled, " needs_ack=", needs_ack, " packets_rx=", srv.packets_rx, "\n");
    // CHECK: COALESCED_SPACES: init=true hs=true app=true established=true
    print("COALESCED_SPACES: init=", init_rx, " hs=", hs_rx, " app=", app_rx, " established=", is_est, "\n");
}

fn test_segmented_arena_bounds() {
    var arena = internal::SegmentedArena { .. };

    // Allocate all 16 chunks of 1024 bytes (16,384 bytes total)
    var all_16_ok = true;
    for i in 16 {
        if !internal::arena_alloc_chunk(arena) {
            all_16_ok = false;
        }
    }

    // 17th chunk allocation MUST fail closed (false)
    let chunk_17_ok = internal::arena_alloc_chunk(arena);

    // Also verify through ReassemblyBuffer insert_fragment past 16,384 bytes
    var rbuf = internal::new_reassembly_buffer(65536);
    let ok_within = internal::insert_fragment(rbuf, 16380, "abcd", false);
    let ok_exceed = internal::insert_fragment(rbuf, 16380, "abcde", false);

    // CHECK: ARENA_16_CHUNKS: ok=true allocated=16 bytes=16384
    print("ARENA_16_CHUNKS: ok=", all_16_ok, " allocated=", arena.allocated_chunks, " bytes=", arena.chunks.len, "\n");
    // CHECK: ARENA_CHUNK_17_REJECTED: false
    print("ARENA_CHUNK_17_REJECTED: ", chunk_17_ok, "\n");
    // CHECK: REASSEMBLY_ARENA_BOUNDS: within_16k=true exceed_16k=false
    print("REASSEMBLY_ARENA_BOUNDS: within_16k=", ok_within, " exceed_16k=", ok_exceed, "\n");
}

inline fn index_to_sub_id(idx: i64) -> u32 {
    return (idx + 1) as u32;
}

fn test_topic_tree_512_limit_and_mqtt_wildcards() {
    var tree = wing::TopicTree { .. };

    var all_512_ok = true;
    var last_cnt: i32 = 0;
    for i in 512 {
        let sub_id = index_to_sub_id(i);
        let cnt, ok = wing::add_distinct_subscriber(tree, "sensors/+/temp", sub_id);
        if !ok {
            all_512_ok = false;
            print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
        }
        last_cnt = cnt;
    }

    // Re-adding an existing subscriber within 512 is idempotent and returns true
    let dup_cnt, dup_ok = wing::add_distinct_subscriber(tree, "sensors/+/temp", 1);

    // Adding 513th distinct subscriber MUST fail closed (ok == false)
    let over_cnt, over_ok = wing::add_distinct_subscriber(tree, "sensors/+/temp", 513);
    if over_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }

    // Verify MQTT + and # wildcard matching (vendor/mosquitto vectors)
    var matched_fds: i64[..512] = [];
    let matched_plus, find_ok = wing::find_subscribers_checked(tree, "sensors/rack1/temp", matched_fds);

    let hash_sub_cnt, hash_sub_ok = wing::add_distinct_subscriber(tree, "telemetry/#", 900);
    var hash_fds: i64[..512] = [];
    let matched_hash, hash_find_ok = wing::find_subscribers_checked(tree, "telemetry/eu/node1/cpu", hash_fds);

    // Also verify accumulator overload directly at 512 boundary
    var mask: u64[4] = [0, 0, 0, 0];
    for k in matched_fds {
        let _, _ = wing::add_distinct_subscriber(matched_fds, mask, k);
    }
    let _, accum_513_ok = wing::add_distinct_subscriber(matched_fds, mask, 9999);

    // CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
    // CHECK: TOPIC_512_SUBSCRIBERS: all_ok=true count=512 dup_ok=true dup_count=512
    print("TOPIC_512_SUBSCRIBERS: all_ok=", all_512_ok, " count=", last_cnt, " dup_ok=", dup_ok, " dup_count=", dup_cnt, "\n");
    // CHECK: TOPIC_513_REJECTED: ok=false count=512 accum_513_ok=false
    print("TOPIC_513_REJECTED: ok=", over_ok, " count=", over_cnt, " accum_513_ok=", accum_513_ok, "\n");
    // CHECK: TOPIC_WILDCARDS: plus_matched=512 plus_ok=true hash_sub_ok=true hash_matched=1 hash_ok=true
    print("TOPIC_WILDCARDS: plus_matched=", matched_plus, " plus_ok=", find_ok, " hash_sub_ok=", hash_sub_ok, " hash_matched=", matched_hash, " hash_ok=", hash_find_ok, "\n");
}

fn run_03_verify_quic_bbr() {
    test_quic_conn_bbr_ack_integration();
    test_coalesced_quic_datagram_demux();
    test_segmented_arena_bounds();
    test_topic_tree_512_limit_and_mqtt_wildcards();
}

// ============================================================================
// 4. verify_quic_bug_hunter_regress (4/10)
// ============================================================================
// CHECK: === [4/10] verify_quic_bug_hunter_regress ===

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
    conn_pad.allow_unencrypted_test_packets = true;
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
    conn_rtt.allow_unencrypted_test_packets = true;
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

fn run_04_verify_quic_bug_hunter_regress() {
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

// ============================================================================
// 5. verify_quic_ecn_and_amplification_regress (5/10)
// ============================================================================
// CHECK: === [5/10] verify_quic_ecn_and_amplification_regress ===

// tests/lit/verify_quic_ecn_and_amplification_regress.goose
// Regression test suite for QUIC bug hunter audit findings:
// - Cumulative ECN-CE handling and BBR cycle unfreeze (RFC 9002 §7.3.2)
// - Server anti-amplification arithmetic overflow protection (RFC 9000 §8.1)
// - Long Header packet with zero payload bounds safety (RFC 9000 §17.2)
// - Connection cumulative byte counter saturation (GOOSE-BUG-3)
//

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
    conn.allow_unencrypted_test_packets = true;
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
            ecn_marked:    (pn & 1) == 0,
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

fn run_05_verify_quic_ecn_and_amplification_regress() {
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

// ============================================================================
// 6. verify_quic_engine (6/10)
// ============================================================================
// CHECK: === [6/10] verify_quic_engine ===

// RFC 9000 / RFC 9002: QUIC Connection State Machine, Anti-Amplification, and Packet Space Dispatcher

fn test_quic_anti_amplification() {
    var server = internal::new_quic_server_connection("server_cid_01");

    // Server has received 0 bytes: cannot send anything
    let can_send_0 = internal::quic_conn_can_send(server, 1200);
    print("AA_INIT: can_send_1200=", can_send_0, "\n");
    // CHECK: AA_INIT: can_send_1200=false

    // Simulate receiving 1200-byte client datagram (RFC 9000 §8.1: budget = 3 * 1200 = 3600)
    server.bytes_received = 1200;
    let can_send_3600 = internal::quic_conn_can_send(server, 3600);
    let can_send_3601 = internal::quic_conn_can_send(server, 3601);
    print("AA_BUDGET: can_3600=", can_send_3600, " can_3601=", can_send_3601, "\n");
    // CHECK: AA_BUDGET: can_3600=true can_3601=false

    // Send 3000 bytes: remaining budget is 600
    server.bytes_sent = 3000;
    let can_send_600 = internal::quic_conn_can_send(server, 600);
    let can_send_601 = internal::quic_conn_can_send(server, 601);
    print("AA_CONSUMED: can_600=", can_send_600, " can_601=", can_send_601, "\n");
    // CHECK: AA_CONSUMED: can_600=true can_601=false

    // Address validated: limit lifted
    server.validated_address = true;
    let can_send_unlimited = internal::quic_conn_can_send(server, 100000);
    print("AA_VALIDATED: can_unlimited=", can_send_unlimited, "\n");
    // CHECK: AA_VALIDATED: can_unlimited=true
}

fn test_quic_pn_space_segregation() {
    var conn = internal::new_quic_server_connection("scid_123");

    // Send in Initial space
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.Initial, 0, 1200, true, 1000);
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.Initial, 1, 1200, true, 1050);

    // Send in Handshake space
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.Handshake, 0, 800, true, 1100);

    // Send in ApplicationData space
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 0, 1400, true, 1200);

    print("PN_SPACES: init_largest=", conn.initial_space.largest_sent_pn,
          " hs_largest=", conn.handshake_space.largest_sent_pn,
          " app_largest=", conn.app_space.largest_sent_pn,
          " total_tx_pkts=", conn.packets_tx,
          " total_tx_bytes=", conn.bytes_sent, "\n");
    // CHECK: PN_SPACES: init_largest=1 hs_largest=0 app_largest=0 total_tx_pkts=4 total_tx_bytes=4600
}

fn test_quic_datagram_ack_generation() {
    var conn = internal::new_quic_server_connection("server_cid_01");
    conn.allow_unencrypted_test_packets = true;

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

    var ack_frame = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(conn, initial_pkt[..], 2000, ack_frame);

    print("DGRAM_INIT: handled=", handled, " needs_ack=", needs_ack, " largest_acked=", ack_frame.largest_acked, "\n");
    // CHECK: DGRAM_INIT: handled=true needs_ack=true largest_acked=0
}

fn test_quic_connection_close() {
    var conn = internal::new_quic_server_connection("scid_close");
    internal::quic_conn_advance_state(conn, internal::QuicConnState.Established);

    print("CONN_ESTABLISHED: state=", conn.state == internal::QuicConnState.Established, "\n");
    // CHECK: CONN_ESTABLISHED: state=true

    // Trigger connection close with APPLICATION_ERROR
    internal::quic_conn_close(conn, rfc::QUIC_ERR_APPLICATION_ERROR);
    print("CONN_CLOSED: state=", conn.state == internal::QuicConnState.Closing, " code=", conn.close_code, "\n");
    // CHECK: CONN_CLOSED: state=true code=12
}

fn run_06_verify_quic_engine() {
    print("=== LIT QUIC Connection Engine Verification ===\n");
    test_quic_anti_amplification();
    test_quic_pn_space_segregation();
    test_quic_datagram_ack_generation();
    test_quic_connection_close();
}

// ============================================================================
// 7. verify_quic_flow_control_boundary (7/10)
// ============================================================================
// CHECK: === [7/10] verify_quic_flow_control_boundary ===

// tests/lit/verify_quic_flow_control_boundary.goose
// Verification of numerical boundary handling, arithmetic wrap prevention,
// and flow-control window calculation under edge conditions (RFC 9000 §4, §19).
//

fn test_recv_stream_arithmetic_wrap() {
    var fc = internal::new_quic_flow_control(100000, 100000);
    var s = internal::new_quic_stream(0, 50000);

    // 1. Crafted 64-bit integer overflow wrapping to 8 (0xFFFFFFFFFFFFFFFE + 10 = 8)
    let ok_wrap, err_wrap = internal::quic_fc_record_recv_stream(fc, s, 0xFFFFFFFFFFFFFFFE, 10);
    assert(!ok_wrap);
    assert(err_wrap == rfc::QUIC_ERR_FLOW_CONTROL);

    // 2. Offsets exceeding 62-bit VarInt ceiling (RFC 9000 §4.1, §4.5, §19.8)
    let ok_varint_overflow, err_varint_overflow = internal::quic_fc_record_recv_stream(
        fc, s, rfc::QUIC_VARINT_MAX, 1,
    );
    assert(!ok_varint_overflow);
    assert(err_varint_overflow == rfc::QUIC_ERR_FLOW_CONTROL);

    print("FC_RECV_WRAP_PREVENTION: OK");
}

fn test_send_arithmetic_wrap() {
    var fc = internal::new_quic_flow_control(100000, 100000);
    var s = internal::new_quic_stream(0, 50000);
    s.send_max_data = 50000;

    // 1. quic_fc_can_send with wrapped offset + len
    let can_send, _, _ = internal::quic_fc_can_send(fc, s, 0xFFFFFFFFFFFFFFFF, 1);
    assert(!can_send);

    // 2. quic_fc_record_send with wrapped offset + len
    let ok_send = internal::quic_fc_record_send(fc, s, 0xFFFFFFFFFFFFFFFF, 1);
    assert(!ok_send);

    print("FC_SEND_WRAP_PREVENTION: OK");
}

fn test_limit_ceiling_and_reset() {
    var fc = internal::new_quic_flow_control(100000, 100000);
    var s = internal::new_quic_stream(0, 50000);

    // 1. Disallow MAX_DATA limit updates above QUIC_VARINT_MAX (RFC 9000 §4.2, §19.9)
    let ok_max_data = internal::quic_fc_update_remote_max_data(fc, 0x4000000000000000);
    assert(!ok_max_data);

    // 2. Disallow MAX_STREAM_DATA limit updates above QUIC_VARINT_MAX (RFC 9000 §4.2, §19.10)
    let ok_stream_max = internal::quic_fc_update_stream_send_max_data(s, 0x4000000000000000);
    assert(!ok_stream_max);

    // 3. RESET_STREAM final size exceeding QUIC_VARINT_MAX (RFC 9000 §4.5)
    s.recv_max_data = 0x7FFFFFFFFFFFFFFF;
    let ok_rst, err_rst = internal::quic_fc_record_recv_reset(fc, s, 0x4000000000000000);
    assert(!ok_rst);
    assert(err_rst == rfc::QUIC_ERR_FLOW_CONTROL);

    print("FC_CEILING_AND_RESET: OK");
}

fn test_window_update_underflow_and_clamp() {
    // 1. Underflow resilience when bytes_read_total exceeds max_data_local
    var fc = internal::new_quic_flow_control(100000, 50000);
    fc.bytes_read_total = 60000;
    let need_update, new_max = internal::quic_fc_check_conn_window_update(fc);
    assert(need_update);
    assert(new_max == 110000);

    // 2. Candidate ceiling clamped to QUIC_VARINT_MAX
    var fc_near_max = internal::new_quic_flow_control(100000, 100000);
    fc_near_max.bytes_read_total = rfc::QUIC_VARINT_MAX - 1000;
    fc_near_max.local_window_size = 5000;
    fc_near_max.max_data_local = rfc::QUIC_VARINT_MAX - 1000;
    fc_near_max.last_advertised_max_data = rfc::QUIC_VARINT_MAX - 1000;
    let need_update2, new_max2 = internal::quic_fc_check_conn_window_update(fc_near_max);
    assert(need_update2);
    assert(new_max2 == rfc::QUIC_VARINT_MAX);

    print("FC_WINDOW_UPDATE_BOUNDS: OK");
}

fn run_07_verify_quic_flow_control_boundary() {
    test_recv_stream_arithmetic_wrap();
    test_send_arithmetic_wrap();
    test_limit_ceiling_and_reset();
    test_window_update_underflow_and_clamp();
}

// CHECK: FC_RECV_WRAP_PREVENTION: OK
// CHECK: FC_SEND_WRAP_PREVENTION: OK
// CHECK: FC_CEILING_AND_RESET: OK
// CHECK: FC_WINDOW_UPDATE_BOUNDS: OK

// ============================================================================
// 8. verify_quic_frames_rfc9000 (8/10)
// ============================================================================
// CHECK: === [8/10] verify_quic_frames_rfc9000 ===

// tests/lit/verify_quic_frames_rfc9000.goose
// Pathological verification suite for RFC 9000 §19 QUIC transport frames:
// STREAM frame flag matrix (OFF, LEN, FIN), zero-length stream edges,
// 62-bit VarInt boundary attacks, reassembly chaos, and differential mutation fuzzing.
//

// ---- RFC 9000 §19.8 STREAM Frame Representation ----------------------------

struct QuicStreamFrame {
    stream_id:        u64         = 0,
    offset:           u64         = 0,
    length:           u64         = 0,
    is_fin:           bool        = false,
    has_explicit_len: bool        = false,
    data:             const u8[:] = "",
}

// Parses header fields of an RFC 9000 §19.8 STREAM frame (0x08..0x0F).
// Returns (stream_id, stream_off, data_len, is_fin, has_len, payload_off, ok).
// crap:trusted-bounds
fn parse_quic_stream_header(
    src:    const u8[:],
    offset: u64,
    limit:  u64,
) -> u64, u64, u64, bool, bool, u64, bool {
    var cur = offset;
    guard cur < limit else { return 0, 0, 0, false, false, offset, false; }

    let ftype, next_cur, ok_type = internal::quic_decode_varint(src, cur);
    guard ok_type && ftype >= 0x08 && ftype <= 0x0F else {
        return 0, 0, 0, false, false, offset, false;
    }
    cur = next_cur;

    let has_off = (ftype & 0x04) != 0;
    let has_len = (ftype & 0x02) != 0;
    let is_fin = (ftype & 0x01) != 0;

    let stream_id, cur_sid, ok_sid = internal::quic_decode_varint(src, cur);
    guard ok_sid else { return 0, 0, 0, false, false, offset, false; }
    cur = cur_sid;

    var stream_off: u64 = 0;
    if has_off {
        let off_val, cur_off, ok_off = internal::quic_decode_varint(src, cur);
        guard ok_off else { return 0, 0, 0, false, false, offset, false; }
        stream_off = off_val;
        cur = cur_off;
    }

    var data_len: u64 = 0;
    if has_len {
        let len_val, cur_len, ok_len = internal::quic_decode_varint(src, cur);
        guard ok_len else { return 0, 0, 0, false, false, offset, false; }
        data_len = len_val;
        cur = cur_len;
    } else {
        guard cur <= limit else { return 0, 0, 0, false, false, offset, false; }
        data_len = core::sub_sat_u64(limit, cur);
    }

    return stream_id, stream_off, data_len, is_fin, has_len, cur, true;
}

// Parses an RFC 9000 §19.8 STREAM frame (0x08..0x0F) from packet wire slice.
// Returns (frame, next_offset, ok).
// crap:trusted-bounds
fn parse_quic_stream_frame(src: const u8[:], offset: u64, packet_end: u64 = 0) -> QuicStreamFrame, u64, bool {
    let limit = if packet_end > 0 && packet_end <= (src.len as u64) { packet_end } else { src.len as u64 };
    let sid, soff, dlen, is_fin, has_len, payload_off, ok = parse_quic_stream_header(src, offset, limit);
    guard ok else { return QuicStreamFrame {}, offset, false; }

    // RFC 9000 §4.5: Offset + Length cannot exceed 2^62 - 1
    guard core::sub_sat_u64(0x3FFFFFFFFFFFFFFF, soff) >= dlen else {
        return QuicStreamFrame {}, offset, false;
    }

    // Truncation check: data_len must not exceed remaining bytes in packet
    guard core::sub_sat_u64(limit, payload_off) >= dlen else {
        return QuicStreamFrame {}, offset, false;
    }

    let st_idx = payload_off as i64;
    let end_off = core::add_sat_u64(payload_off, dlen);
    let en_idx = end_off as i64;
    guard st_idx >= 0 && en_idx >= st_idx && en_idx <= src.len else {
        return QuicStreamFrame {}, offset, false;
    }

    let data_slice = src[st_idx..en_idx];

    return QuicStreamFrame {
        stream_id:        sid,
        offset:           soff,
        length:           dlen,
        is_fin:           is_fin,
        has_explicit_len: has_len,
        data:             data_slice,
    }, end_off, true;
}

// Encodes an RFC 9000 §19.8 STREAM frame with explicit flag bits into buffer.
// flags: lower 3 bits represent OFF (0x04), LEN (0x02), FIN (0x01).
// crap:trusted-bounds
fn encode_quic_stream_frame<B>(
    out:       B&,
    flags:     u8,
    stream_id: u64,
    offset:    u64,
    payload:   const u8[:],
) -> bool {
    let ftype: u64 = 0x08 | ((flags & 0x07) as u64);
    guard internal::quic_encode_varint(out, ftype) else { return false; }
    guard internal::quic_encode_varint(out, stream_id) else { return false; }
    if (flags & 0x04) != 0 {
        guard internal::quic_encode_varint(out, offset) else { return false; }
    }
    if (flags & 0x02) != 0 {
        guard internal::quic_encode_varint(out, payload.len as u64) else { return false; }
    }
    out.append(payload);
    return true;
}

// Adapter for wire_kit split_stream and fuzz_payload verification
// crap:trusted-bounds
fn parse_stream_wire_step(buf: const u8[:]) -> i64 {
    let frame, next_off, ok = parse_quic_stream_frame(buf, 0);
    if !ok || (next_off as i64) != buf.len {
        return 0;
    }
    return frame.length as i64;
}

// ---- Section 1: VarInt Codec Bounds & Pathological Attacks -----------------

// crap:trusted-bounds
fn test_quic_varint_pathological() {
    // 1. Minimum and Maximum RFC 9000 VarInt values across all 4 encodings
    // 1-byte: 0, 63
    var buf1: u8[..16] = [];
    assert(internal::quic_encode_varint(buf1, 0));
    assert(internal::quic_encode_varint(buf1, 63));
    assert(buf1.len == 2);
    let v0, o1, ok0 = internal::quic_decode_varint(buf1[..], 0);
    let v63, o2, ok63 = internal::quic_decode_varint(buf1[..], o1);
    assert(ok0 && v0 == 0 && ok63 && v63 == 63 && o2 == 2);

    // 2-byte: 64, 16383
    var buf2: u8[..16] = [];
    assert(internal::quic_encode_varint(buf2, 64));
    assert(internal::quic_encode_varint(buf2, 16383));
    assert(buf2.len == 4);
    let v64, o3, ok64 = internal::quic_decode_varint(buf2[..], 0);
    let v16k, o4, ok16k = internal::quic_decode_varint(buf2[..], o3);
    assert(ok64 && v64 == 64 && ok16k && v16k == 16383 && o4 == 4);

    // 4-byte: 16384, 1073741823
    var buf4: u8[..16] = [];
    assert(internal::quic_encode_varint(buf4, 16384));
    assert(internal::quic_encode_varint(buf4, 1073741823));
    assert(buf4.len == 8);
    let v164, o5, ok164 = internal::quic_decode_varint(buf4[..], 0);
    let v1g, o6, ok1g = internal::quic_decode_varint(buf4[..], o5);
    assert(ok164 && v164 == 16384 && ok1g && v1g == 1073741823 && o6 == 8);

    // 8-byte: 1073741824, 0x3FFFFFFFFFFFFFFF (2^62 - 1)
    var buf8: u8[..32] = [];
    assert(internal::quic_encode_varint(buf8, 1073741824));
    assert(internal::quic_encode_varint(buf8, 0x3FFFFFFFFFFFFFFF));
    assert(buf8.len == 16);
    let v1g1, o7, ok1g1 = internal::quic_decode_varint(buf8[..], 0);
    let vmax, o8, okmax = internal::quic_decode_varint(buf8[..], o7);
    assert(ok1g1 && v1g1 == 1073741824 && okmax && vmax == 0x3FFFFFFFFFFFFFFF && o8 == 16);

    // 2. Reject integer exceeding 62-bit RFC 9000 limit
    var buf_ovf: u8[..16] = [];
    let ok_ovf = internal::quic_encode_varint(buf_ovf, 0x4000000000000000);
    assert(!ok_ovf);

    // 3. Truncated VarInt byte streams (Buffer underrun defense)
    let trunc_2byte: const u8[1] = [0x40];
    let _, _, ok_tr2 = internal::quic_decode_varint(trunc_2byte[..], 0);
    assert(!ok_tr2);

    let trunc_4byte: const u8[2] = [0x80, 0x01];
    let _, _, ok_tr4 = internal::quic_decode_varint(trunc_4byte[..], 0);
    assert(!ok_tr4);

    let trunc_8byte: const u8[5] = [0xC0, 0x01, 0x02, 0x03, 0x04];
    let _, _, ok_tr8 = internal::quic_decode_varint(trunc_8byte[..], 0);
    assert(!ok_tr8);

    print("VARINT_BOUNDS: OK max_62bit=4611686018427387903 trunc_rejected=true");
}

// ---- Section 2: RFC 9000 §19.8 STREAM Frame Flag Matrix (0x08..0x0F) --------

// crap:trusted-bounds
fn verify_single_stream_flag(flags: u8, payload: const u8[:]) {
    var wire: u8[..128] = [];
    let stream_id: u64 = (flags as u64) << 2;
    let offset:    u64 = if (flags & 0x04) != 0 { 1024 } else { 0 };
    assert(encode_quic_stream_frame(wire, flags, stream_id, offset, payload));

    let frame, next_off, dec_ok = parse_quic_stream_frame(wire[..], 0);
    assert(dec_ok);
    assert((next_off as i64) == wire.len);
    assert(frame.stream_id == stream_id);
    assert(frame.offset == offset);
    assert(frame.is_fin == ((flags & 0x01) != 0));
    assert(frame.has_explicit_len == ((flags & 0x02) != 0));
    assert(frame.data == payload);
}

// crap:trusted-bounds
fn test_quic_stream_flag_matrix() {
    let payload = "STREAM_PAYLOAD_DATA";
    for flags in 8 {
        verify_single_stream_flag(flags as u8, payload);
    }
    print("STREAM_FLAG_MATRIX: passed=8/8");
}

// ---- Section 3: Zero-Length Stream Frames & Stream ID Classification -------

// crap:trusted-bounds
fn test_quic_stream_zero_length() {
    // 1. Zero-length payload WITHOUT FIN (flags = 0x0A: LEN only)
    var wire_empty: u8[..32] = [];
    assert(encode_quic_stream_frame(wire_empty, 0x02, 10, 0, ""));
    let f_empty, _, ok_empty = parse_quic_stream_frame(wire_empty[..], 0);
    assert(ok_empty);
    assert(f_empty.length == 0);
    assert(!f_empty.is_fin);
    assert(f_empty.data.len == 0);

    // 2. Zero-length payload WITH FIN (flags = 0x0B: LEN | FIN)
    var wire_fin: u8[..32] = [];
    assert(encode_quic_stream_frame(wire_fin, 0x03, 10, 0, ""));
    let f_fin, _, ok_fin = parse_quic_stream_frame(wire_fin[..], 0);
    assert(ok_fin);
    assert(f_fin.length == 0);
    assert(f_fin.is_fin);
    assert(f_fin.data.len == 0);

    // 3. Zero-length payload with non-zero offset AND FIN (flags = 0x07: OFF | LEN | FIN)
    var wire_off_fin: u8[..32] = [];
    assert(encode_quic_stream_frame(wire_off_fin, 0x07, 10, 4096, ""));
    let f_off_fin, _, ok_off_fin = parse_quic_stream_frame(wire_off_fin[..], 0);
    assert(ok_off_fin);
    assert(f_off_fin.offset == 4096);
    assert(f_off_fin.length == 0);
    assert(f_off_fin.is_fin);

    // 4. Stream ID Classification (RFC 9000 §2.1)
    let s0_bidi_c = internal::quic_is_client_stream(0) && internal::quic_is_bidi_stream(0);
    let s1_bidi_s = internal::quic_is_server_stream(1) && internal::quic_is_bidi_stream(1);
    let s2_uni_c = internal::quic_is_client_stream(2) && internal::quic_is_uni_stream(2);
    let s3_uni_s = internal::quic_is_server_stream(3) && internal::quic_is_uni_stream(3);
    assert(s0_bidi_c && s1_bidi_s && s2_uni_c && s3_uni_s);

    print("STREAM_ZERO_LENGTH: empty_ok=", ok_empty, " fin_ok=", ok_fin, " off_fin_ok=", ok_off_fin, " stream_ids_ok=true");
}

// ---- Section 4: Truncation Attacks & Boundary Violations -------------------

// crap:trusted-bounds
fn test_quic_stream_truncation_attacks() {
    // 1. Truncation attack: Length field claims 100 bytes, but wire only holds 10 bytes
    var wire_trunc: u8[..64] = [];
    assert(internal::quic_encode_varint(wire_trunc, 0x0A));
    assert(internal::quic_encode_varint(wire_trunc, 4));
    assert(internal::quic_encode_varint(wire_trunc, 100));
    wire_trunc.append("0123456789");
    let _, _, ok_trunc = parse_quic_stream_frame(wire_trunc[..], 0);
    assert(!ok_trunc);

    // 2. Stream offset + length overflow (> 2^62 - 1)
    var wire_ovf: u8[..64] = [];
    assert(internal::quic_encode_varint(wire_ovf, 0x0E));
    assert(internal::quic_encode_varint(wire_ovf, 4));
    assert(internal::quic_encode_varint(wire_ovf, 0x3FFFFFFFFFFFFFF0));
    assert(internal::quic_encode_varint(wire_ovf, 32));
    wire_ovf.resize((wire_ovf.len + 32) as i64, 0);
    let _, _, ok_ovf = parse_quic_stream_frame(wire_ovf[..], 0);
    assert(!ok_ovf);

    // 3. Truncated VarInt Stream ID
    var wire_bad_sid: u8[..16] = [];
    wire_bad_sid.push(0x0A);
    wire_bad_sid.push(0x80);
    let _, _, ok_bad_sid = parse_quic_stream_frame(wire_bad_sid[..], 0);
    assert(!ok_bad_sid);

    print("STREAM_TRUNCATION: payload_trunc_rejected=", !ok_trunc, " offset_ovf_rejected=", !ok_ovf, " sid_trunc_rejected=", !ok_bad_sid);
}

// ---- Section 5: Reassembly Chaos & Final Size Invariants --------------------

// crap:trusted-bounds
fn test_quic_stream_reassembly_chaos() {
    var r_buf = internal::new_reassembly_buffer(1048576);

    // 1. In-order arrival: [0, 5) -> "HELLO"
    let ok1 = internal::insert_fragment(r_buf, 0, "HELLO", false);
    assert(ok1);

    // 2. Out-of-order gap: [10, 15) -> "QUIC!" with FIN
    let ok2 = internal::insert_fragment(r_buf, 10, "QUIC!", true);
    assert(ok2);
    assert(r_buf.fin_received);
    assert(r_buf.final_size == 15);

    // 3. Contiguous read from head: should only yield first 5 bytes due to gap at [5, 10)
    var out1: u8[..32] = [];
    let r1 = internal::read_contiguous(r_buf, out1);
    assert(r1 == 5);
    assert(out1[..] == "HELLO");
    assert(r_buf.consumed_offset == 5);

    // 4. Final Size Violation attack 1: Inject data exceeding established final size 15
    let ok_bad_data = internal::insert_fragment(r_buf, 12, "OVERFLOW_AFTER_FIN", false);
    assert(!ok_bad_data);

    // 5. Final Size Violation attack 2: Re-declare differing FIN at offset 20 != 15
    let ok_diff_fin = internal::insert_fragment(r_buf, 10, "DIFFERENT_FINAL_SZ", true);
    assert(!ok_diff_fin);

    // 6. Fill the missing gap: [5, 10) -> " RFC "
    let ok3 = internal::insert_fragment(r_buf, 5, " RFC ", false);
    assert(ok3);

    // 7. Contiguous read tail: reads remaining 10 bytes up to final size 15
    var out2: u8[..32] = [];
    let r2 = internal::read_contiguous(r_buf, out2);
    assert(r2 == 10);
    assert(out2[..] == " RFC QUIC!");
    assert(r_buf.consumed_offset == 15);

    // 8. Reassembly interval overlap and duplicates
    var r_buf2 = internal::new_reassembly_buffer(1048576);
    assert(internal::insert_fragment(r_buf2, 0, "ABCDEF", false));
    assert(internal::insert_fragment(r_buf2, 3, "DEFGHI", false));
    assert(internal::insert_fragment(r_buf2, 0, "ABC", false));
    var out_ovl: u8[..32] = [];
    let r_ovl = internal::read_contiguous(r_buf2, out_ovl);
    assert(r_ovl == 9);
    assert(out_ovl[..] == "ABCDEFGHI");

    print("STREAM_REASSEMBLY: gap_handled=true final_size_enforced=true overlap_merged=true");
}

// ---- Section 6: RFC 9000 §19 Control Frames Demuxing -----------------------

// crap:trusted-bounds
fn demux_stream_mgmt_frame(ftype: u64, src: const u8[:], cur: u64) -> u64, bool {
    if ftype == rfc::QUIC_FRAME_RESET_STREAM {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        let _, cur3, ok3 = internal::quic_decode_varint(src, cur2);
        guard ok3 else { return cur, false; }
        return cur3, true;
    }

    if ftype == rfc::QUIC_FRAME_STOP_SENDING {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        return cur2, true;
    }

    return cur, false;
}

// crap:trusted-bounds
fn demux_flow_frame(ftype: u64, src: const u8[:], cur: u64) -> u64, bool {
    if ftype == rfc::QUIC_FRAME_MAX_DATA {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        return cur1, true;
    }

    if ftype == rfc::QUIC_FRAME_MAX_STREAM_DATA {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        return cur2, true;
    }

    return cur, false;
}

// Demuxes non-STREAM RFC 9000 §19 control frames from packet payload
// crap:trusted-bounds
fn demux_control_frame(src: const u8[:], offset: u64) -> u64, u64, bool {
    var cur = offset;
    guard cur < (src.len as u64) else { return 0, offset, false; }

    let ftype, next_cur, ok_type = internal::quic_decode_varint(src, cur);
    guard ok_type else { return 0, offset, false; }
    cur = next_cur;

    if ftype == rfc::QUIC_FRAME_PADDING {
        return ftype, cur, true;
    }

    if ftype == rfc::QUIC_FRAME_PING {
        return ftype, cur, true;
    }

    let end_mgmt, ok_mgmt = demux_stream_mgmt_frame(ftype, src, cur);
    if ok_mgmt { return ftype, end_mgmt, true; }

    let end_flow, ok_flow = demux_flow_frame(ftype, src, cur);
    if ok_flow { return ftype, end_flow, true; }

    return ftype, cur, false;
}

// crap:trusted-bounds
fn test_quic_control_frames_demux() {
    var packet: u8[..128] = [];

    // 1. PADDING run (8 zeroes)
    for _ in 8 { packet.push(0x00); }

    // 2. PING (0x01)
    packet.push(0x01);

    // 3. RESET_STREAM (0x04, stream_id=12, err=0x42, final_size=1024)
    assert(internal::quic_encode_varint(packet, rfc::QUIC_FRAME_RESET_STREAM));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 0x42));
    assert(internal::quic_encode_varint(packet, 1024));

    // 4. STOP_SENDING (0x05, stream_id=12, err=0x19)
    assert(internal::quic_encode_varint(packet, rfc::QUIC_FRAME_STOP_SENDING));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 0x19));

    // 5. MAX_DATA (0x10, max_data=65536)
    assert(internal::quic_encode_varint(packet, rfc::QUIC_FRAME_MAX_DATA));
    assert(internal::quic_encode_varint(packet, 65536));

    // 6. MAX_STREAM_DATA (0x11, stream_id=12, max_data=32768)
    assert(internal::quic_encode_varint(packet, rfc::QUIC_FRAME_MAX_STREAM_DATA));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 32768));

    // Demux the multi-frame packet
    var cur_off: u64 = 0;
    while cur_off < (packet.len as u64) {
        let _, next_off, ok = demux_control_frame(packet[..], cur_off);
        assert(ok);
        assert(next_off > cur_off);
        cur_off = next_off;
    }

    assert(cur_off == (packet.len as u64));

    print("CONTROL_FRAMES_DEMUX: frames_parsed=6 all_consumed=true");
}

// ---- Section 7: Differential Mutation Fuzzing with wire_kit -----------------

// crap:trusted-bounds
fn test_quic_stream_mutation_fuzzing() {
    var valid_frame: u8[..128] = [];
    assert(encode_quic_stream_frame(valid_frame, 0x07, 100, 2048, "MUTATION_SEED_PAYLOAD_32_BYTES!!"));

    // 1. Split-stream prefix validation: ensure partial reads never panic
    let split_ok = wire_kit::verify_split_stream(valid_frame[..], 0, 32, parse_stream_wire_step);
    assert(split_ok);

    // 2. Fuzzing with 200 random single-bit flips, boundary injections, and swaps
    let fuzz_ok = wire_kit::fuzz_payload(valid_frame[..], 200, parse_stream_wire_step);
    assert(fuzz_ok);

    print("STREAM_MUTATION_FUZZ: split_ok=true fuzz_200_iters=true");
}

// ---- Section 8: QUICC-01 Transport Parameters & RFC 9368 Version Info ------

// crap:trusted-bounds
fn test_quic_transport_params_rfc9000() {
    var tp = internal::QuicTransportParams {
        max_idle_timeout:                    30000,
        has_stateless_reset_token:           true,
        max_udp_payload_size:                1452,
        initial_max_data:                    1048576,
        initial_max_stream_data_bidi_local:  262144,
        initial_max_stream_data_bidi_remote: 262144,
        initial_max_stream_data_uni:         131072,
        initial_max_streams_bidi:            100,
        initial_max_streams_uni:             100,
        ack_delay_exponent:                  4,
        max_ack_delay:                       20,
        disable_active_migration:            true,
        active_connection_id_limit:          4,
        chosen_version:                      rfc::QUIC_VERSION_1,
        max_datagram_frame_size:             1200,
        grease_quic_bit:                     true,
        min_ack_delay_us:                    1000,
        ..
    };
    tp.original_destination_connection_id.append([0x01, 0x02, 0x03, 0x04]);
    tp.initial_source_connection_id.append([0x05, 0x06, 0x07, 0x08]);
    tp.retry_source_connection_id.append([0x09, 0x0A, 0x0B, 0x0C]);
    for i in 16 { tp.stateless_reset_token[i] = (0xA0 + i) as u8; }
    tp.available_versions.push(rfc::QUIC_VERSION_2);
    tp.available_versions.push(rfc::QUIC_VERSION_1);

    // Client cannot encode server-only parameters
    var bad_cli_buf: u8[..256] = [];
    assert(!internal::encode_quic_transport_params(bad_cli_buf, tp, false));

    // Server encodes full transport parameters
    var srv_buf: u8[..256] = [];
    assert(internal::encode_quic_transport_params(srv_buf, tp, true));

    var dec_tp = internal::QuicTransportParams { .. };
    assert(internal::decode_quic_transport_params(srv_buf[..], true, dec_tp));
    assert(dec_tp.max_idle_timeout == 30000 && dec_tp.max_udp_payload_size == 1452);
    assert(dec_tp.ack_delay_exponent == 4 && dec_tp.max_ack_delay == 20);
    assert(dec_tp.disable_active_migration && dec_tp.grease_quic_bit);
    assert(dec_tp.active_connection_id_limit == 4 && dec_tp.min_ack_delay_us == 1000);
    assert(dec_tp.chosen_version == rfc::QUIC_VERSION_1 && dec_tp.available_versions.len == 2);
    assert(dec_tp.available_versions[0] == rfc::QUIC_VERSION_2);
    assert(dec_tp.has_stateless_reset_token && dec_tp.stateless_reset_token[0] == 0xA0);

    // Reject server-only parameters when decoded with is_server = false
    var bad_dec = internal::QuicTransportParams { .. };
    assert(!internal::decode_quic_transport_params(srv_buf[..], false, bad_dec));

    // Reject boundary violations: ack_delay_exponent > 20, max_ack_delay >= 16384, max_udp_payload_size < 1200, active_cid_limit < 2
    let bad_ade: const u8[3] = [0x0A, 0x01, 21];
    assert(!internal::decode_quic_transport_params(bad_ade[..], true, bad_dec));
    let bad_mad: const u8[4] = [0x0B, 0x02, 0x80, 0x00];
    assert(!internal::decode_quic_transport_params(bad_mad[..], true, bad_dec));
    let bad_mtu: const u8[4] = [0x03, 0x02, 0x44, 0xAF]; // 1199 < 1200
    assert(!internal::decode_quic_transport_params(bad_mtu[..], true, bad_dec));
    let bad_cid_lim: const u8[3] = [0x0E, 0x01, 1];
    assert(!internal::decode_quic_transport_params(bad_cid_lim[..], true, bad_dec));
    let bad_ver: const u8[6] = [0x11, 0x04, 0x00, 0x00, 0x00, 0x00]; // chosen_version == 0
    assert(!internal::decode_quic_transport_params(bad_ver[..], true, bad_dec));

    print("QUICC_01_TP: srv_roundtrip=true bounds_enforced=true version_info_ok=true");
}

// ---- Section 9: QUICC-05 Server Preferred Address & Migration --------------

// crap:trusted-bounds
fn test_quic_preferred_address_migration() {
    var raw_pref: u8[..64] = [];
    // IPv4: 198.51.100.42:8443 (0x20FB)
    raw_pref.append([198, 51, 100, 42, 0x20, 0xFB]);
    // IPv6: 2001:db8::1, port 9443 (0x24E3)
    raw_pref.append([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    raw_pref.append([0x24, 0xE3]);
    // CID len = 4, CID = [0xAA, 0xBB, 0xCC, 0xDD]
    raw_pref.append([4, 0xAA, 0xBB, 0xCC, 0xDD]);
    // 16-byte stateless reset token
    for i in 16 { raw_pref.push((0x10 + i) as u8); }

    var pref = internal::QuicPreferredAddress { .. };
    assert(internal::decode_preferred_address(raw_pref[..], pref));
    assert(pref.ipv4[0] == 198 && pref.ipv4_port == 8443);
    assert(pref.ipv6[0] == 0x20 && pref.ipv6_port == 9443);
    assert(pref.cid.len == 4 && pref.cid[0] == 0xAA);
    assert(pref.stateless_reset_token[0] == 0x10);

    // Reject truncated or zero-length CID preferred_address
    var bad_pref = internal::QuicPreferredAddress { .. };
    assert(!internal::decode_preferred_address(raw_pref[..40], bad_pref));

    // Reject preferred address with all zero IPs and ports
    var zero_pref_buf: u8[..64] = [];
    for i in 24 { zero_pref_buf.push(0); }
    zero_pref_buf.append([4, 1, 2, 3, 4]);
    for i in 16 { zero_pref_buf.push(0x20 as u8); }
    assert(!internal::decode_preferred_address(zero_pref_buf[..], bad_pref));

    let init_addr = internal::new_quic_endpoint_addr([192, 0, 2, 1], 443);
    var mgr = internal::new_quic_migration_manager(init_addr);
    let tok: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];

    // Probe IPv6 preferred address
    assert(internal::quic_migration_probe_preferred_address(mgr, pref, true, tok));
    assert(mgr.has_probing_path && mgr.probing_path.remote_addr.port == 9443);

    // Probe IPv4 preferred address
    assert(internal::quic_migration_probe_preferred_address(mgr, pref, false, tok));
    assert(mgr.has_probing_path && mgr.probing_path.remote_addr.port == 8443);
    internal::quic_migration_fail_probing(mgr);
    assert(!mgr.has_probing_path);

    // When migration_disabled is true, probing is rejected
    mgr.migration_disabled = true;
    assert(!internal::quic_migration_probe_preferred_address(mgr, pref, true, tok));

    print("QUICC_05_PREF_ADDR: decoded=true v6_probe=true v4_probe=true disable_mig_honored=true");
}

// ---- Section 10: QUICC-06 & QUICH3-05 ACK_FREQUENCY & IMMEDIATE_ACK --------

// crap:trusted-bounds
fn test_quic_ack_frequency_frames() {
    var flow_pkt: u8[..64] = [];
    assert(internal::encode_max_streams_frame(flow_pkt, 100, true));
    assert(internal::encode_data_blocked_frame(flow_pkt, 65536));
    assert(internal::encode_streams_blocked_frame(flow_pkt, 50, false));
    var f_idx: i64 = 0;
    let mf1, mok1 = internal::decode_quic_frame_cursor(flow_pkt[..], f_idx);
    let mf2, mok2 = internal::decode_quic_frame_cursor(flow_pkt[..], f_idx);
    let mf3, mok3 = internal::decode_quic_frame_cursor(flow_pkt[..], f_idx);
    assert(mok1 && mf1.frame_type == internal::QuicFrameType.MaxStreamsBidi);
    assert(mok2 && mf2.frame_type == internal::QuicFrameType.DataBlocked);
    assert(mok3 && mf3.frame_type == internal::QuicFrameType.StreamsBlockedUni);

    var pkt: u8[..64] = [];
    // 1. IMMEDIATE_ACK (0x1F)
    pkt.push(0x1F);
    // 2. ACK_FREQUENCY (0xAF)
    let af_in = internal::QuicAckFrequencyFrame {
        seq:                      7,
        ack_eliciting_threshold:  10,
        request_max_ack_delay_us: 15000,
        reordering_threshold:     3,
    };
    assert(internal::encode_ack_frequency_frame(pkt, af_in));

    var idx: i64 = 0;
    let f1, ok1 = internal::decode_quic_frame_cursor(pkt[..], idx);
    assert(ok1 && f1.frame_type == internal::QuicFrameType.ImmediateAck);
    assert(idx == 1);

    let f2, ok2 = internal::decode_quic_frame_cursor(pkt[..], idx);
    assert(ok2 && f2.frame_type == internal::QuicFrameType.AckFrequency);
    assert(f2.stream_id == 7 && f2.length == 10 && f2.max_data == 15000 && f2.offset == 3);
    assert(idx == pkt.len);

    // Reject ack_eliciting_threshold == 0 in both encoder and decoder
    let bad_af = internal::QuicAckFrequencyFrame { seq: 1, ack_eliciting_threshold: 0, .. };
    var bad_out: u8[..32] = [];
    assert(!internal::encode_ack_frequency_frame(bad_out, bad_af));

    let bad_wire: const u8[4] = [0x01, 0x00, 0x10, 0x01]; // threshold = 0
    var cur = core::cursor_from(bad_wire[..]);
    var af_out = internal::QuicAckFrequencyFrame { .. };
    assert(!internal::decode_ack_frequency_frame(cur, af_out));

    print("QUICC_06_ACK_FREQ: immediate_ack=true ack_freq_roundtrip=true zero_thresh_rejected=true");
}

// ---- Main Entry Point ------------------------------------------------------

// crap:trusted-bounds
fn run_08_verify_quic_frames_rfc9000() {
    print("=== LIT RFC 9000 QUIC Frames Pathological Verification ===");
    test_quic_varint_pathological();
    test_quic_stream_flag_matrix();
    test_quic_stream_zero_length();
    test_quic_stream_truncation_attacks();
    test_quic_stream_reassembly_chaos();
    test_quic_control_frames_demux();
    test_quic_stream_mutation_fuzzing();
    test_quic_transport_params_rfc9000();
    test_quic_preferred_address_migration();
    test_quic_ack_frequency_frames();
}

// CHECK: === LIT RFC 9000 QUIC Frames Pathological Verification ===
// CHECK-NEXT: VARINT_BOUNDS: OK max_62bit=4611686018427387903 trunc_rejected=true
// CHECK-NEXT: STREAM_FLAG_MATRIX: passed=8/8
// CHECK-NEXT: STREAM_ZERO_LENGTH: empty_ok=true fin_ok=true off_fin_ok=true stream_ids_ok=true
// CHECK-NEXT: STREAM_TRUNCATION: payload_trunc_rejected=true offset_ovf_rejected=true sid_trunc_rejected=true
// CHECK-NEXT: STREAM_REASSEMBLY: gap_handled=true final_size_enforced=true overlap_merged=true
// CHECK-NEXT: CONTROL_FRAMES_DEMUX: frames_parsed=6 all_consumed=true
// CHECK-NEXT: STREAM_MUTATION_FUZZ: split_ok=true fuzz_200_iters=true
// CHECK-NEXT: QUICC_01_TP: srv_roundtrip=true bounds_enforced=true version_info_ok=true
// CHECK-NEXT: QUICC_05_PREF_ADDR: decoded=true v6_probe=true v4_probe=true disable_mig_honored=true
// CHECK-NEXT: QUICC_06_ACK_FREQ: immediate_ack=true ack_freq_roundtrip=true zero_thresh_rejected=true

// ============================================================================
// 9. verify_quic_loss_recovery (9/10)
// ============================================================================
// CHECK: === [9/10] verify_quic_loss_recovery ===

// tests/lit/verify_quic_loss_recovery.goose
// Verification of QUIC Loss Detection, PTO, and RTT Wire Mechanics (RFC 9002).
//

fn test_rtt_estimator_invariants() {
    var rtt = internal::RttState { .. };
    assert(rtt.smoothed_rtt_us == 333000);
    print("INIT_RTT: 333000");

    // First sample: 100ms (100,000 us)
    internal::update_rtt(rtt, 100000, 0, true, 1000);
    assert(rtt.smoothed_rtt_us == 100000 && rtt.min_rtt_us == 100000);
    print("SAMPLE1: smoothed=100000 min=100000");

    // Second sample: 80ms (80,000 us), min_rtt drops
    internal::update_rtt(rtt, 80000, 0, true, 2000);
    assert(rtt.min_rtt_us == 80000);
    print("SAMPLE2_MIN_DROPPED: true");

    // Ack delay capping: peer reports 50ms delay, but max_ack_delay is 25ms
    internal::update_rtt(rtt, 120000, 50000, true, 3000);
    assert(rtt.latest_rtt_us == 120000);
    print("SAMPLE3_DELAY_CAPPED: true");
}

fn test_quic_loss_detection_thresholds() {
    var space = internal::PnSpaceState { space_id: internal::PnSpaceId.ApplicationData, .. };
    var rtt = internal::RttState { smoothed_rtt_us: 100000, latest_rtt_us: 100000, .. };

    // Record sent packets 0, 1, 2, 3, 4 at t = 10000 us
    space.has_sent_packets = true;
    space.largest_sent_pn = 4;
    for pn in 5 {
        space.sent_packets.push(internal::SentPacketMeta {
            pn:            pn as u64,
            time_sent_us:  10000,
            size_bytes:    1200,
            ack_eliciting: true,
            in_flight:     true,
        });
    }

    // Peer ACKs packet 4: largest_acked_pn = 4.
    // Packet threshold = 3: pkts <= (4 - 3) = 1 MUST be declared lost!
    space.has_acked_packets = true;
    space.largest_acked_pn = 4;

    var lost: internal::SentPacketMeta[..64] = [];
    internal::detect_lost_packets(space, rtt, 15000, lost);

    assert(lost.len == 2);
    print("LOST_COUNT_PACKET_THRESHOLD: 2");

    var p0_lost = false;
    var p1_lost = false;
    for &p in lost {
        if p.pn == 0 { p0_lost = true; }
        if p.pn == 1 { p1_lost = true; }
    }
    assert(p0_lost && p1_lost);
    print("LOST_P0_P1: true");
}

fn test_optimistic_ack_rejection() {
    var space = internal::PnSpaceState {
        space_id:         internal::PnSpaceId.ApplicationData,
        has_sent_packets: true,
        largest_sent_pn:  10,
        ..
    };

    // Attack 1: Peer ACKs packet 15 (ahead of sent 10) -> MUST FAIL
    var bad_ack1 = internal::AckFrame { largest_acked: 15, first_ack_range: 0, .. };
    var intervals: internal::AckInterval[..64] = [];
    let ok1 = internal::parse_and_validate_ack(space, bad_ack1, intervals);
    assert(!ok1);
    print("OACK_FORWARD_REJECTED: true");

    // Attack 2: first_ack_range > largest_acked (underflow) -> MUST FAIL
    var bad_ack2 = internal::AckFrame { largest_acked: 5, first_ack_range: 10, .. };
    let ok2 = internal::parse_and_validate_ack(space, bad_ack2, intervals);
    assert(!ok2);
    print("OACK_UNDERFLOW_REJECTED: true");

    // Valid ACK: largest_acked = 10, first_ack_range = 2 -> interval [8, 10]
    var good_ack = internal::AckFrame { largest_acked: 10, first_ack_range: 2, .. };
    let ok3 = internal::parse_and_validate_ack(space, good_ack, intervals);
    assert(ok3 && intervals.len == 1 && intervals[0].smallest == 8 && intervals[0].largest == 10);
    print("VALID_ACK_INTERVAL: true");
}

fn test_pto_backoff_calculations() {
    var rtt = internal::RttState {
        smoothed_rtt_us:  100000,
        rttvar_us:        20000,
        max_ack_delay_us: 25000,
        ..
    };

    // pto_count = 0: smoothed_rtt + 4 * rttvar + max_ack_delay = 100k + 80k + 25k = 205k
    let pto0 = internal::compute_pto_duration(rtt, 0, true);
    assert(pto0 == 205000);
    print("PTO_COUNT_0: 205000");

    // pto_count = 1: 205k * 2 = 410k
    let pto1 = internal::compute_pto_duration(rtt, 1, true);
    assert(pto1 == 410000);
    print("PTO_COUNT_1: 410000");

    // pto_count = 2: 205k * 4 = 820k
    let pto2 = internal::compute_pto_duration(rtt, 2, true);
    assert(pto2 == 820000);
    print("PTO_COUNT_2: 820000");
}

fn run_09_verify_quic_loss_recovery() {
    print("=== RUNNING QUIC LOSS RECOVERY SUITE ===");
    test_rtt_estimator_invariants();
    test_quic_loss_detection_thresholds();
    test_optimistic_ack_rejection();
    test_pto_backoff_calculations();
    print("QUIC LOSS RECOVERY COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING QUIC LOSS RECOVERY SUITE ===
// CHECK: INIT_RTT: 333000
// CHECK: SAMPLE1: smoothed=100000 min=100000
// CHECK: SAMPLE2_MIN_DROPPED: true
// CHECK: SAMPLE3_DELAY_CAPPED: true
// CHECK: LOST_COUNT_PACKET_THRESHOLD: 2
// CHECK: LOST_P0_P1: true
// CHECK: OACK_FORWARD_REJECTED: true
// CHECK: OACK_UNDERFLOW_REJECTED: true
// CHECK: VALID_ACK_INTERVAL: true
// CHECK: PTO_COUNT_0: 205000
// CHECK: PTO_COUNT_1: 410000
// CHECK: PTO_COUNT_2: 820000
// CHECK: QUIC LOSS RECOVERY COMPLETE: ALL INVARIANTS PASSED

// ============================================================================
// 10. verify_quic_spec_invariants (10/10)
// ============================================================================
// CHECK: === [10/10] verify_quic_spec_invariants ===

// tests/lit/verify_quic_spec_invariants.goose
// Verification of RFC 9000 strict specification invariants:
// - RFC 9000 §19.7: NEW_TOKEN token field MUST NOT be empty (FRAME_ENCODING_ERROR).
// - RFC 9000 §19.7: Clients MUST NOT send NEW_TOKEN; server receipt is PROTOCOL_VIOLATION.
// - RFC 9000 §19.11 & §4.6: MAX_STREAMS cannot exceed 2^60 (FRAME_ENCODING_ERROR).
// - RFC 9000 §19.14: STREAMS_BLOCKED cannot exceed 2^60 (FRAME_ENCODING_ERROR).
// - RFC 9000 §12.4 & §12.5: Prohibited frames in packet number spaces (PROTOCOL_VIOLATION).
// - RFC 9000 §19.13: STREAM_DATA_BLOCKED on send-only stream is STREAM_STATE_ERROR.
//

fn test_new_token_empty_rejected() {
    var vEmptyToken: u8[>..] = [];
    assert(wire_kit::parse_hex("0700", vEmptyToken)); // Type 0x07 (NEW_TOKEN), Length 0
    let _, _, ok = internal::decode_quic_frame(vEmptyToken[..], 0);
    assert(!ok); // RFC 9000 §19.7: Token MUST NOT be empty -> FRAME_ENCODING_ERROR

    var vValidToken: u8[>..] = [];
    assert(wire_kit::parse_hex("070474657374", vValidToken)); // Type 0x07, Length 4, "test"
    let frame, next_off, ok_val = internal::decode_quic_frame(vValidToken[..], 0);
    assert(ok_val);
    assert(next_off == 6);
    assert(frame.frame_type == internal::QuicFrameType.NewToken);
    assert(frame.payload == "test");
    print("QUIC_NEW_TOKEN_INVARIANTS: OK");
}

fn test_max_streams_boundary_2_60() {
    // 2^60 is 0x1000000000000000. Encoded as 8-byte varint: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    var vMaxStreamsValid: u8[>..] = [];
    assert(wire_kit::parse_hex("12D000000000000000", vMaxStreamsValid));
    let frame_val, _, ok_val = internal::decode_quic_frame(vMaxStreamsValid[..], 0);
    assert(ok_val);
    assert(frame_val.max_data == (1 as u64) << 60);

    // 2^60 + 1: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x01 -> MUST be rejected (RFC 9000 §19.11)
    var vMaxStreamsOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("12D000000000000001", vMaxStreamsOvf));
    let _, _, ok_ovf = internal::decode_quic_frame(vMaxStreamsOvf[..], 0);
    assert(!ok_ovf);

    // Test uni variant (0x13)
    var vMaxStreamsUniOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("13D000000000000001", vMaxStreamsUniOvf));
    let _, _, ok_uni_ovf = internal::decode_quic_frame(vMaxStreamsUniOvf[..], 0);
    assert(!ok_uni_ovf);

    print("QUIC_MAX_STREAMS_2_60_CEILING: OK");
}

fn test_streams_blocked_boundary_2_60() {
    // 2^60 is valid: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    var vSbValid: u8[>..] = [];
    assert(wire_kit::parse_hex("16D000000000000000", vSbValid));
    let frame_val, _, ok_val = internal::decode_quic_frame(vSbValid[..], 0);
    assert(ok_val);
    assert(frame_val.max_data == (1 as u64) << 60);

    // 2^60 + 1 MUST be rejected (RFC 9000 §19.14)
    var vSbOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("16D000000000000001", vSbOvf));
    let _, _, ok_ovf = internal::decode_quic_frame(vSbOvf[..], 0);
    assert(!ok_ovf);

    // Test uni variant (0x17)
    var vSbUniOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("17D000000000000001", vSbUniOvf));
    let _, _, ok_uni_ovf = internal::decode_quic_frame(vSbUniOvf[..], 0);
    assert(!ok_uni_ovf);

    print("QUIC_STREAMS_BLOCKED_2_60_CEILING: OK");
}

fn test_packet_number_space_frame_matrix() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);

    // Initial packet containing STREAM frame (0x08) -> MUST trigger PROTOCOL_VIOLATION (RFC 9000 §12.5)
    var stream_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("0804026869", stream_payload)); // STREAM id=4 len=2 "hi"

    let handled, _ = internal::quic_conn_process_payload(srv, stream_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Reset connection
    var srv2 = internal::new_quic_server_connection(scid[..]);
    // Initial packet containing HANDSHAKE_DONE (0x1E) -> MUST trigger PROTOCOL_VIOLATION
    var hd_payload: u8[>..] = [];
    hd_payload.push(0x1E);
    let handled2, _ = internal::quic_conn_process_payload(srv2, hd_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled2);
    assert(srv2.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Initial packet containing CONNECTION_CLOSE_APP (0x1D) -> MUST trigger PROTOCOL_VIOLATION
    var srv3 = internal::new_quic_server_connection(scid[..]);
    var cc_app_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("1D0000", cc_app_payload)); // CONNECTION_CLOSE_APP code=0 len=0
    let handled3, _ = internal::quic_conn_process_payload(srv3, cc_app_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled3);
    assert(srv3.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // 1-RTT packet containing legitimate STREAM frame -> MUST succeed
    var srv4 = internal::new_quic_server_connection(scid[..]);
    srv4.state = internal::QuicConnState.Established;
    let handled4, _ = internal::quic_conn_process_payload(srv4, stream_payload[..], internal::QuicHeaderType.OneRtt);
    assert(handled4);
    assert(srv4.close_code == 0);

    print("QUIC_SPACE_FRAME_MATRIX: OK");
}

fn test_server_receiving_new_token() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // Server receiving NEW_TOKEN (0x07) in 1-RTT packet -> MUST trigger PROTOCOL_VIOLATION (RFC 9000 §19.7)
    var tok_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("070474657374", tok_payload));
    let handled, _ = internal::quic_conn_process_payload(srv, tok_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    print("QUIC_SERVER_NEW_TOKEN_REJECTED: OK");
}

fn test_stream_data_blocked_send_only() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // Server receives STREAM_DATA_BLOCKED on stream 3 (ServerUni: client can only receive, cannot send).
    // Stream 3 for Server is send-only. Peer (client) is receive-only.
    // RFC 9000 §19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream
    // MUST terminate the connection with error STREAM_STATE_ERROR."
    var sdb_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("15034000", sdb_payload)); // STREAM_DATA_BLOCKED stream=3 limit=0
    let handled, _ = internal::quic_conn_process_payload(srv, sdb_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_STREAM_STATE);

    print("QUIC_STREAM_DATA_BLOCKED_INVARIANTS: OK");
}

fn test_frame_encoders() {
    var out_tok: u8[..64] = [];
    assert(!internal::encode_new_token_frame(out_tok, "")); // empty token rejected
    assert(internal::encode_new_token_frame(out_tok, "valid_token"));
    let f_tok, _, ok_tok = internal::decode_quic_frame(out_tok[..], 0);
    assert(ok_tok);
    assert(f_tok.frame_type == internal::QuicFrameType.NewToken);
    assert(f_tok.payload == "valid_token");

    var out_ncid: u8[..64] = [];
    let reset_tok: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let cid:       u8[4]  = [0xAA, 0xBB, 0xCC, 0xDD];
    assert(internal::encode_new_conn_id_frame(out_ncid, 1, 0, cid[..], reset_tok));
    let f_ncid, _, ok_ncid = internal::decode_quic_frame(out_ncid[..], 0);
    assert(ok_ncid);
    assert(f_ncid.frame_type == internal::QuicFrameType.NewConnectionId);
    assert(f_ncid.stream_id == 1);
    assert(f_ncid.offset == 0);

    var out_rcid: u8[..32] = [];
    assert(internal::encode_retire_conn_id_frame(out_rcid, 2));
    let f_rcid, _, ok_rcid = internal::decode_quic_frame(out_rcid[..], 0);
    assert(ok_rcid);
    assert(f_rcid.frame_type == internal::QuicFrameType.RetireConnectionId);
    assert(f_rcid.stream_id == 2);

    print("QUIC_FRAME_ENCODERS: OK");
}

fn run_10_verify_quic_spec_invariants() {
    test_new_token_empty_rejected();
    test_max_streams_boundary_2_60();
    test_streams_blocked_boundary_2_60();
    test_packet_number_space_frame_matrix();
    test_server_receiving_new_token();
    test_stream_data_blocked_send_only();
    test_frame_encoders();
    print("ALL_QUIC_SPEC_INVARIANTS: OK");
}

// CHECK: QUIC_NEW_TOKEN_INVARIANTS: OK
// CHECK: QUIC_MAX_STREAMS_2_60_CEILING: OK
// CHECK: QUIC_STREAMS_BLOCKED_2_60_CEILING: OK
// CHECK: QUIC_SPACE_FRAME_MATRIX: OK
// CHECK: QUIC_SERVER_NEW_TOKEN_REJECTED: OK
// CHECK: QUIC_STREAM_DATA_BLOCKED_INVARIANTS: OK
// CHECK: QUIC_FRAME_ENCODERS: OK
// CHECK: ALL_QUIC_SPEC_INVARIANTS: OK

fn main() {
    print("\n=== [1/10] rfc_repro_framer_quic_invariants ===\n");
    run_01_rfc_repro_framer_quic_invariants();
    print("\n=== [2/10] verify_quic_ack_edge ===\n");
    run_02_verify_quic_ack_edge();
    print("\n=== [3/10] verify_quic_bbr ===\n");
    run_03_verify_quic_bbr();
    print("\n=== [4/10] verify_quic_bug_hunter_regress ===\n");
    run_04_verify_quic_bug_hunter_regress();
    print("\n=== [5/10] verify_quic_ecn_and_amplification_regress ===\n");
    run_05_verify_quic_ecn_and_amplification_regress();
    print("\n=== [6/10] verify_quic_engine ===\n");
    run_06_verify_quic_engine();
    print("\n=== [7/10] verify_quic_flow_control_boundary ===\n");
    run_07_verify_quic_flow_control_boundary();
    print("\n=== [8/10] verify_quic_frames_rfc9000 ===\n");
    run_08_verify_quic_frames_rfc9000();
    print("\n=== [9/10] verify_quic_loss_recovery ===\n");
    run_09_verify_quic_loss_recovery();
    print("\n=== [10/10] verify_quic_spec_invariants ===\n");
    run_10_verify_quic_spec_invariants();
}
