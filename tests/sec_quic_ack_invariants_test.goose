// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Security invariant tests for QUIC Transport (RFC 9000, RFC 9002):
// 1. ACK Frame encoding, decoding, and RFC 9000 §19.3.1 underflow defense.
// 2. Optimistic ACK (OACK) attack prevention.
// 3. QUIC packet header fixed and reserved bits validation.
import std;
import core from "..";
import wing from "..";

fn test_quic_ack_frame_decoding_invariants(t: core::T&) {
    // 1. Valid ACK Frame
    var ack = wing::AckFrame {
        is_ecn: false,
        largest_acked: 100,
        ack_delay: 25,
        first_ack_range: 10,
        ..
    };
    var wire: u8[..64] = [];
    t.assert_true(wing::encode_ack_frame(wire, ack), "encode ack frame");

    let dec_ack, read_len, ok = wing::decode_ack_frame(wire[..], 0);
    t.assert_true(ok, "decode valid ack frame");
    t.assert_eq(dec_ack.largest_acked, 100, "largest acked matches");
    t.assert_eq(dec_ack.first_ack_range, 10, "first range matches");
    t.assert_eq(dec_ack.ack_delay, 25, "delay matches");

    // 2. RFC 9000 §19.3.1: Largest Acknowledged < First ACK Range must be rejected
    // Type 0x02, Largest Acked = 5, Delay = 0, Range Count = 0, First Range = 10
    let bad_wire: const u8[5] = [0x02, 0x05, 0x00, 0x00, 0x0A];
    let _, _, bad_ok = wing::decode_ack_frame(bad_wire[..], 0);
    t.assert_false(bad_ok, "largest_acked < first_ack_range must be rejected");

    // 3. Range gap underflow: subsequent range underflows packet number space
    // Type 0x02, Largest = 10, Delay = 0, Range Count = 1, First Range = 5 (smallest = 5),
    // Gap = 10 (needs 5 - 10 - 2, underflow!)
    let bad_gap_wire: const u8[7] = [0x02, 0x0A, 0x00, 0x01, 0x05, 0x0A, 0x01];
    let _, _, bad_gap_ok = wing::decode_ack_frame(bad_gap_wire[..], 0);
    t.assert_false(bad_gap_ok, "range gap underflowing PN space must be rejected");
}

fn test_quic_oack_defense(t: core::T&) {
    var space = wing::PnSpaceState {
        has_sent_packets: true,
        largest_sent_pn: 50,
        ..
    };

    // Forward-dated ACK (largest_acked = 60 > largest_sent_pn = 50)
    var fwd_ack = wing::AckFrame {
        largest_acked: 60,
        first_ack_range: 0,
        ..
    };
    var intervals: wing::AckInterval[..64] = [];
    let ok_fwd = wing::parse_and_validate_ack(space, fwd_ack, intervals);
    t.assert_false(ok_fwd, "OACK forward-dated packet number must be rejected");

    // Valid ACK within sent range
    var valid_ack = wing::AckFrame {
        largest_acked: 50,
        first_ack_range: 5,
        ..
    };
    let ok_valid = wing::parse_and_validate_ack(space, valid_ack, intervals);
    t.assert_true(ok_valid, "valid ack within sent range passes");
    t.assert_eq(intervals.len, 1, "1 interval extracted");
    t.assert_eq(intervals[0].smallest, 45, "smallest is 45");
    t.assert_eq(intervals[0].largest, 50, "largest is 50");
}

fn test_quic_header_security_bits(t: core::T&) {
    // 1. Long Header Fixed Bit (0x40) check: byte 0 = 0x80 (Long=1, Fixed=0)
    let bad_fixed_long: const u8[12] = [0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_fixed = wing::parse_quic_header(bad_fixed_long[..]);
    t.assert_false(ok_fixed, "long header with fixed bit cleared must be rejected");

    // 2. Long Header Initial Reserved Bits (0x0C) check: byte 0 = 0xC4 (Reserved bit set)
    let bad_res_long: const u8[12] = [0xC4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_res = wing::parse_quic_header(bad_res_long[..]);
    t.assert_false(ok_res, "long header with reserved bits set must be rejected");

    // 3. Short Header Fixed Bit (0x40) check: byte 0 = 0x00 (Fixed=0)
    let bad_fixed_short: const u8[8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_fix = wing::parse_quic_header(bad_fixed_short[..], 4);
    t.assert_false(ok_short_fix, "short header with fixed bit cleared must be rejected");

    // 4. Short Header Reserved Bits (0x18) check: byte 0 = 0x58 (Fixed=1, Reserved bit 4 set)
    let bad_res_short: const u8[8] = [0x58, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_res = wing::parse_quic_header(bad_res_short[..], 4);
    t.assert_false(ok_short_res, "short header with reserved bits set must be rejected");
}

fn main() {
    var runner = core::new_runner("QUIC Transport Security Invariants Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. QUIC ACK Frame Decoding Invariants", test_quic_ack_frame_decoding_invariants);
    core::run_case(runner, "2. QUIC OACK Attack Prevention", test_quic_oack_defense);
    core::run_case(runner, "3. QUIC Header Security Bits", test_quic_header_security_bits);
    let ok = core::finish(runner);
    assert(ok);
}
