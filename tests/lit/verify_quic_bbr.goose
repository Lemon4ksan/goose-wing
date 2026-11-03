// RUN: goose check %s
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Native LIT verification suite for QUIC BBRv3 integration, coalesced packet demuxing,
// bounded 16-chunk SegmentedArena stream reassembly, and TopicTree 512-subscriber
// fail-closed capacity enforcement with MQTT wildcard matching.
import std;
import core from "../..";
import wing from "../..";

fn test_quic_conn_bbr_ack_integration() {
    var conn = internal::new_quic_server_connection("srv_bbr_01");
    conn.state = internal::QuicConnState.Established;
    conn.validated_address = true;

    // Record 4 in-flight ApplicationData packets (1200 bytes each) across rounds
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 1, 1200, true, 10000);
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 2, 1200, true, 20000);
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 3, 1200, true, 30000);
    internal::quic_conn_record_sent(conn, internal::PnSpaceId.ApplicationData, 4, 1200, true, 40000);

    // Acknowledge packets 1..3 in 3 sequential ACK events to advance BBR Startup -> Drain
    let ack1 = internal::AckFrame {
        largest_acked:   1,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok1 = internal::quic_conn_on_ack(conn, ack1, 30000, internal::PnSpaceId.ApplicationData);

    let ack2 = internal::AckFrame {
        largest_acked:   2,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok2 = internal::quic_conn_on_ack(conn, ack2, 45000, internal::PnSpaceId.ApplicationData);

    let ack3 = internal::AckFrame {
        largest_acked:   3,
        ack_delay:       0,
        first_ack_range: 0,
        ..
    };
    let ok3 = internal::quic_conn_on_ack(conn, ack3, 60000, internal::PnSpaceId.ApplicationData);

    // Trigger congestion signal via ECN-CE on packet 4 ACK
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

fn main() {
    test_quic_conn_bbr_ack_integration();
    test_coalesced_quic_datagram_demux();
    test_segmented_arena_bounds();
    test_topic_tree_512_limit_and_mqtt_wildcards();
}
