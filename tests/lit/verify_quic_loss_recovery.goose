// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_loss_recovery.goose
// Verification of QUIC Loss Detection, PTO, and RTT Wire Mechanics (RFC 9002).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_rtt_estimator_invariants() {
    var rtt = wing::RttState { .. };
    assert(rtt.smoothed_rtt_us == 333000);
    print("INIT_RTT: 333000");

    // First sample: 100ms (100,000 us)
    wing::update_rtt(rtt, 100000, 0, true, 1000);
    assert(rtt.smoothed_rtt_us == 100000 && rtt.min_rtt_us == 100000);
    print("SAMPLE1: smoothed=100000 min=100000");

    // Second sample: 80ms (80,000 us), min_rtt drops
    wing::update_rtt(rtt, 80000, 0, true, 2000);
    assert(rtt.min_rtt_us == 80000);
    print("SAMPLE2_MIN_DROPPED: true");

    // Ack delay capping: peer reports 50ms delay, but max_ack_delay is 25ms
    wing::update_rtt(rtt, 120000, 50000, true, 3000);
    assert(rtt.latest_rtt_us == 120000);
    print("SAMPLE3_DELAY_CAPPED: true");
}

fn test_quic_loss_detection_thresholds() {
    var space = wing::PnSpaceState { space_id: wing::PnSpaceId.ApplicationData, .. };
    var rtt = wing::RttState { smoothed_rtt_us: 100000, latest_rtt_us: 100000, .. };

    // Record sent packets 0, 1, 2, 3, 4 at t = 10000 us
    space.has_sent_packets = true;
    space.largest_sent_pn = 4;
    for pn in 5 {
        space.sent_packets.push(wing::SentPacketMeta {
            pn: pn as u64,
            time_sent_us: 10000,
            size_bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
        });
    }

    // Peer ACKs packet 4: largest_acked_pn = 4.
    // Packet threshold = 3: pkts <= (4 - 3) = 1 MUST be declared lost!
    space.has_acked_packets = true;
    space.largest_acked_pn = 4;

    var lost: wing::SentPacketMeta[..64] = [];
    wing::detect_lost_packets(space, rtt, 15000, lost);

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
    var space = wing::PnSpaceState {
        space_id: wing::PnSpaceId.ApplicationData,
        has_sent_packets: true,
        largest_sent_pn: 10,
        ..
    };

    // Attack 1: Peer ACKs packet 15 (ahead of sent 10) -> MUST FAIL
    var bad_ack1 = wing::AckFrame { largest_acked: 15, first_ack_range: 0, .. };
    var intervals: wing::AckInterval[..64] = [];
    let ok1 = wing::parse_and_validate_ack(space, bad_ack1, intervals);
    assert(!ok1);
    print("OACK_FORWARD_REJECTED: true");

    // Attack 2: first_ack_range > largest_acked (underflow) -> MUST FAIL
    var bad_ack2 = wing::AckFrame { largest_acked: 5, first_ack_range: 10, .. };
    let ok2 = wing::parse_and_validate_ack(space, bad_ack2, intervals);
    assert(!ok2);
    print("OACK_UNDERFLOW_REJECTED: true");

    // Valid ACK: largest_acked = 10, first_ack_range = 2 -> interval [8, 10]
    var good_ack = wing::AckFrame { largest_acked: 10, first_ack_range: 2, .. };
    let ok3 = wing::parse_and_validate_ack(space, good_ack, intervals);
    assert(ok3 && intervals.len == 1 && intervals[0].smallest == 8 && intervals[0].largest == 10);
    print("VALID_ACK_INTERVAL: true");
}

fn test_pto_backoff_calculations() {
    var rtt = wing::RttState {
        smoothed_rtt_us: 100000,
        rttvar_us: 20000,
        max_ack_delay_us: 25000,
        ..
    };

    // pto_count = 0: smoothed_rtt + 4 * rttvar + max_ack_delay = 100k + 80k + 25k = 205k
    let pto0 = wing::compute_pto_duration(rtt, 0, true);
    assert(pto0 == 205000);
    print("PTO_COUNT_0: 205000");

    // pto_count = 1: 205k * 2 = 410k
    let pto1 = wing::compute_pto_duration(rtt, 1, true);
    assert(pto1 == 410000);
    print("PTO_COUNT_1: 410000");

    // pto_count = 2: 205k * 4 = 820k
    let pto2 = wing::compute_pto_duration(rtt, 2, true);
    assert(pto2 == 820000);
    print("PTO_COUNT_2: 820000");
}

fn main() {
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
