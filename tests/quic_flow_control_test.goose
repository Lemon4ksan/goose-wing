// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Flow Control & RFC 9000 Hardening Test Suite.
// Covers connection-level MAX_DATA, stream-level MAX_STREAM_DATA, credit exhaustion,
// monotonic updates, FLOW_CONTROL_ERROR violations, RESET_STREAM accounting,
// auto-window update thresholds, Appendix A packet number reconstruction,
// and QuicConnection inbound frame demuxing.
import std;
import core from "..";
import wing from "..";

fn test_connection_flow_control_budget(t: core::T&) {
    var fc = wing::new_quic_flow_control(1000, 65536); // Remote limit 1000
    var s0 = wing::new_quic_stream(0, 65536);
    s0.send_max_data = 10000; // Unlimited stream credit

    t.assert_eq(wing::quic_fc_remaining_conn_credit(fc), 1000, "initial conn credit 1000");

    // Send 600 bytes on stream 0
    let can_send1, blk_s1, blk_c1 = wing::quic_fc_can_send(fc, s0, 0, 600);
    t.assert_true(can_send1, "can send 600 bytes");
    t.assert_false(blk_s1, "not blocked on stream");
    t.assert_false(blk_c1, "not blocked on conn");

    let ok_send1 = wing::quic_fc_record_send(fc, s0, 0, 600);
    t.assert_true(ok_send1, "record send 600 ok");
    t.assert_eq(fc.bytes_sent_total, 600, "bytes_sent_total 600");
    t.assert_eq(wing::quic_fc_remaining_conn_credit(fc), 400, "conn credit remaining 400");
    t.assert_false(fc.is_data_blocked, "not blocked yet");

    // Send remaining 400 bytes on stream 4
    var s4 = wing::new_quic_stream(4, 65536);
    s4.send_max_data = 10000;

    let ok_send2 = wing::quic_fc_record_send(fc, s4, 0, 400);
    t.assert_true(ok_send2, "record send 400 on s4 ok");
    t.assert_eq(fc.bytes_sent_total, 1000, "bytes_sent_total 1000");
    t.assert_eq(wing::quic_fc_remaining_conn_credit(fc), 0, "conn credit exhausted");
    t.assert_true(fc.is_data_blocked, "marked data blocked");

    // Attempt to send 1 additional byte on stream 0
    let can_send3, blk_s3, blk_c3 = wing::quic_fc_can_send(fc, s0, 600, 1);
    t.assert_false(can_send3, "cannot send when conn credit is 0");
    t.assert_false(blk_s3, "stream has credit");
    t.assert_true(blk_c3, "blocked on conn credit");

    let ok_send3 = wing::quic_fc_record_send(fc, s0, 600, 1);
    t.assert_false(ok_send3, "record send fails when conn budget exceeded");
}

fn test_monotonic_remote_max_data(t: core::T&) {
    var fc = wing::new_quic_flow_control(500, 65536);
    var s = wing::new_quic_stream(0, 65536);
    s.send_max_data = 5000;

    let _ = wing::quic_fc_record_send(fc, s, 0, 500);
    t.assert_true(fc.is_data_blocked, "connection is blocked at 500");

    // Non-monotonic / decreasing update MUST be rejected
    let rej_down = wing::quic_fc_update_remote_max_data(fc, 400);
    t.assert_false(rej_down, "reject lower MAX_DATA 400");
    t.assert_eq(fc.max_data_remote, 500, "limit remains 500");
    t.assert_true(fc.is_data_blocked, "remains blocked");

    // Stale identical update MUST be rejected
    let rej_same = wing::quic_fc_update_remote_max_data(fc, 500);
    t.assert_false(rej_same, "reject identical MAX_DATA 500");

    // Monotonic increase unblocks connection
    let ok_up = wing::quic_fc_update_remote_max_data(fc, 1200);
    t.assert_true(ok_up, "accept higher MAX_DATA 1200");
    t.assert_eq(fc.max_data_remote, 1200, "limit updated to 1200");
    t.assert_false(fc.is_data_blocked, "connection unblocked");
    t.assert_eq(wing::quic_fc_remaining_conn_credit(fc), 700, "remaining credit 700");

    // Sending now succeeds
    let can_send, _, _ = wing::quic_fc_can_send(fc, s, 500, 200);
    t.assert_true(can_send, "send 200 succeeds after unblocking");
}

fn test_stream_flow_control_budget(t: core::T&) {
    var fc = wing::new_quic_flow_control(100000, 65536); // Unlimited conn credit
    var s = wing::new_quic_stream(0, 65536);
    s.send_max_data = 300; // 300 bytes stream budget

    t.assert_eq(wing::quic_fc_remaining_stream_credit(s), 300, "stream credit 300");

    // Send 200 bytes
    let ok1 = wing::quic_fc_record_send(fc, s, 0, 200);
    t.assert_true(ok1, "send 200 bytes ok");
    t.assert_eq(s.bytes_sent, 200, "stream bytes sent 200");
    t.assert_eq(wing::quic_fc_remaining_stream_credit(s), 100, "stream remaining credit 100");

    // Attempting to send 150 bytes exceeds stream budget (200 + 150 = 350 > 300)
    let can_send_excess, blk_s, blk_c = wing::quic_fc_can_send(fc, s, 200, 150);
    t.assert_false(can_send_excess, "cannot exceed stream limit");
    t.assert_true(blk_s, "blocked on stream limit");
    t.assert_false(blk_c, "connection not blocked");

    let ok_excess = wing::quic_fc_record_send(fc, s, 200, 150);
    t.assert_false(ok_excess, "record send exceeds stream budget fails");

    // Receive MAX_STREAM_DATA increasing limit to 800
    let ok_update = wing::quic_fc_update_stream_send_max_data(s, 800);
    t.assert_true(ok_update, "stream limit updated to 800");
    t.assert_eq(s.send_max_data, 800, "s.send_max_data is 800");
    t.assert_eq(wing::quic_fc_remaining_stream_credit(s), 600, "stream credit now 600");

    // Now sending 150 bytes succeeds
    let ok2 = wing::quic_fc_record_send(fc, s, 200, 150);
    t.assert_true(ok2, "send 150 succeeds after MAX_STREAM_DATA");
    t.assert_eq(s.bytes_sent, 350, "stream bytes sent 350");
}

fn test_ingress_flow_control_and_errors(t: core::T&) {
    var fc = wing::new_quic_flow_control(10000, 1000); // Local conn limit 1000
    var s = wing::new_quic_stream(0, 500); // Local stream limit 500

    // Ingress 400 bytes at offset 0
    let ok1, err1 = wing::quic_fc_record_recv_stream(fc, s, 0, 400);
    t.assert_true(ok1, "recv 400 bytes ok");
    t.assert_eq(err1, wing::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 400, "stream bytes_recv 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn bytes_recv_total 400");

    // Re-transmission / duplicate interval (offset 100, len 100) MUST NOT inflate conn total
    let ok_dup, _ = wing::quic_fc_record_recv_stream(fc, s, 100, 100);
    t.assert_true(ok_dup, "duplicate interval accepted");
    t.assert_eq(s.bytes_recv, 400, "bytes_recv still 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn total not inflated by retransmission");

    // Ingress exceeding stream limit (offset 400, len 150 -> end 550 > 500)
    let ok_stream_violation, err_stream_violation = wing::quic_fc_record_recv_stream(fc, s, 400, 150);
    t.assert_false(ok_stream_violation, "stream flow control violation rejected");
    t.assert_eq(err_stream_violation, wing::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");

    // Now test connection-level ingress violation with another stream
    var s4 = wing::new_quic_stream(4, 2000); // Large stream limit
    // Current conn total is 400. Conn limit is 1000.
    // Ingress 500 bytes on s4 -> conn total = 900 <= 1000 (ok)
    let ok2, _ = wing::quic_fc_record_recv_stream(fc, s4, 0, 500);
    t.assert_true(ok2, "recv 500 bytes on s4 ok");
    t.assert_eq(fc.bytes_recv_total, 900, "conn total 900");

    // Ingress 200 bytes on s4 -> 900 + 200 = 1100 > 1000 -> Connection FLOW_CONTROL_ERROR
    let ok_conn_violation, err_conn_violation = wing::quic_fc_record_recv_stream(fc, s4, 500, 200);
    t.assert_false(ok_conn_violation, "connection flow control violation rejected");
    t.assert_eq(err_conn_violation, wing::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");
}

fn test_reset_stream_flow_control_accounting(t: core::T&) {
    var fc = wing::new_quic_flow_control(10000, 1000);
    var s = wing::new_quic_stream(0, 800);

    // Stream had received 200 bytes
    let _ = wing::quic_fc_record_recv_stream(fc, s, 0, 200);
    t.assert_eq(fc.bytes_recv_total, 200, "conn total 200");

    // RESET_STREAM arrives with final_size = 500.
    // Additional 300 bytes committed to connection total.
    let ok_rst, err_rst = wing::quic_fc_record_recv_reset(fc, s, 500);
    t.assert_true(ok_rst, "reset final size 500 accepted");
    t.assert_eq(err_rst, wing::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "stream bytes_recv set to final size 500");
    t.assert_eq(fc.bytes_recv_total, 500, "conn total advanced to 500");

    // RESET_STREAM with final size exceeding connection limit (e.g. 1200 > 1000)
    var s4 = wing::new_quic_stream(4, 2000);
    let ok_rst_exceed, err_rst_exceed = wing::quic_fc_record_recv_reset(fc, s4, 1200);
    t.assert_false(ok_rst_exceed, "reset exceeding conn limit rejected");
    t.assert_eq(err_rst_exceed, wing::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR");
}

fn test_window_update_thresholds(t: core::T&) {
    // Configure local window of 64KB (65536)
    var fc = wing::new_quic_flow_control(65536, 65536);
    var s = wing::new_quic_stream(0, 65536);

    // App reads 20000 bytes. Available credit: 65536 - 20000 = 45536 > 32768 (half window)
    wing::quic_fc_on_app_read(fc, s, 20000);
    let need_update1, _ = wing::quic_fc_check_conn_window_update(fc);
    t.assert_false(need_update1, "no MAX_DATA update before threshold (credit > half)");

    // App reads another 15000 bytes. Total read = 35000.
    // Available credit: 65536 - 35000 = 30536 < 32768 (credit < half window)
    wing::quic_fc_on_app_read(fc, s, 15000);
    let need_update2, new_max_data = wing::quic_fc_check_conn_window_update(fc);
    t.assert_true(need_update2, "MAX_DATA update triggered when available < half window");
    t.assert_eq(new_max_data, 100536, "new MAX_DATA is consumed (35000) + window (65536) = 100536");
    t.assert_eq(fc.max_data_local, 100536, "local max data updated");

    // Immediately checking again returns false (already advertised)
    let need_update3, _ = wing::quic_fc_check_conn_window_update(fc);
    t.assert_false(need_update3, "subsequent check does not re-trigger without more reads");

    // Stream window update threshold test
    var s_up = wing::new_quic_stream(0, 1000);
    s_up.recv_consumed = 600; // Read 600 bytes out of 1000. Available = 400 < 500 (half)
    let s_need, s_new_limit = wing::quic_fc_check_stream_window_update(s_up, 1000);
    t.assert_true(s_need, "MAX_STREAM_DATA triggered");
    t.assert_eq(s_new_limit, 1600, "new stream limit is 600 + 1000 = 1600");
}

fn test_rfc9000_packet_number_decoding(t: core::T&) {
    // Vector 1 from RFC 9000 Appendix A:
    // largest_pn = 0xABE8B, truncated_pn = 0xACEB, pn_nbits = 16 (2 bytes)
    // expected reconstructed PN = 0x0AACEB (699627)
    let pn1 = wing::decode_packet_number(0xABE8B, 0xACEB, 2);
    t.assert_eq(pn1, 0x0AACEB, "RFC 9000 Appendix A Vector 1 decoded correctly");

    let pn1_chk, ok1 = wing::decode_packet_number_checked(0xABE8B, 0xACEB, 2);
    t.assert_true(ok1, "checked decode vector 1 ok");
    t.assert_eq(pn1_chk, 0x0AACEB, "checked decode vector 1 matches");

    // 1-byte packet number (8 bits, window 256):
    // largest_pn = 100, truncated = 105 -> 105
    let pn_1b = wing::decode_packet_number(100, 105, 1);
    t.assert_eq(pn_1b, 105, "1-byte PN near largest");

    // 1-byte wrapping around window:
    // largest_pn = 250, truncated = 5 -> candidate = 250 - 250 + 5 = 5.
    // candidate + 256 = 261. Diff |261 - 250| = 11 < |5 - 250| = 245.
    // Decoded PN = 261!
    let pn_wrap = wing::decode_packet_number(250, 5, 1);
    t.assert_eq(pn_wrap, 261, "1-byte PN wrapping around 256");

    // 3-byte packet number (24 bits, window 0x1000000):
    let pn_3b = wing::decode_packet_number(0x1000000, 0x000010, 3);
    t.assert_eq(pn_3b, 0x1000010, "3-byte PN window reconstruction");

    // 4-byte packet number (32 bits, window 0x100000000):
    let pn_4b = wing::decode_packet_number(0x200000000, 0x00000005, 4);
    t.assert_eq(pn_4b, 0x200000005, "4-byte PN window reconstruction");

    // Invalid length (0 or > 4) MUST fail in checked version
    let _, ok_inv0 = wing::decode_packet_number_checked(100, 10, 0);
    t.assert_false(ok_inv0, "0-byte length rejected");

    let _, ok_inv5 = wing::decode_packet_number_checked(100, 10, 5);
    t.assert_false(ok_inv5, "5-byte length rejected");
}

fn test_connection_datagram_demuxing(t: core::T&) {
    let scid: u8[4] = [0x01, 0x02, 0x03, 0x04];
    var conn = wing::new_quic_server_connection(scid[..]);

    // Construct a synthetic 1-RTT packet:
    // Byte 0: 0x40 (Short header, 1-RTT, 1-byte PN)
    // Bytes 1..4: DCID (same as conn.scid)
    // Byte 5: Packet Number (0x01)
    // Bytes 6..: STREAM frame (Type 0x08 = OFF=0, LEN=0, FIN=0), Stream ID = 0, Payload = "WING"
    var dgram: u8[..128] = [];
    dgram.push(0x40); // Short header
    dgram.append(scid[..]); // 4-byte DCID
    dgram.push(0x01); // PN = 1

    // Encode STREAM frame into dgram: Stream ID 0 (Client Bidi), offset 0, len 4, fin false
    let ok_enc = wing::encode_stream_frame(dgram, 0, 0, "WING", wing::QuicStreamFlags { fin: true, with_len: false });
    t.assert_true(ok_enc, "stream frame encoded into datagram");

    var out_ack = wing::AckFrame { .. };
    let handled, needs_ack = wing::quic_conn_process_datagram(conn, dgram[..], 1000, out_ack);
    t.assert_true(handled, "datagram handled successfully");
    t.assert_true(needs_ack, "STREAM frame is ack-eliciting, needs_ack is true");

    // Verify stream state in connection
    t.assert_eq(conn.stream_table.streams.len, 1, "stream table has 1 stream");
    t.assert_eq(conn.stream_table.streams[0].stream_id, 0, "stream 0 registered");
    t.assert_eq(conn.stream_table.streams[0].bytes_recv, 4, "stream 0 received 4 bytes");
    t.assert_eq(conn.flow_ctrl.bytes_recv_total, 4, "flow control recorded 4 bytes received");

    // Now test connection-level ingress violation with exceeding payload
    let scid2: u8[4] = [0x05, 0x06, 0x07, 0x08];
    var conn2 = wing::new_quic_server_connection(scid2[..]);
    conn2.flow_ctrl.max_data_local = 10; // Low limit

    var dgram2: u8[..128] = [];
    dgram2.push(0x40);
    dgram2.append(scid2[..]);
    dgram2.push(0x02);

    let _ = wing::encode_stream_frame(
        dgram2, 0, 0, "0123456789ABCDEFGHIJ",
        wing::QuicStreamFlags { fin: true, with_len: false },
    ); // 20 bytes > 10

    var out_ack2 = wing::AckFrame { .. };
    let handled2, _ = wing::quic_conn_process_datagram(conn2, dgram2[..], 2000, out_ack2);
    t.assert_false(handled2, "violating datagram returns handled=false");
    t.assert_eq(conn2.state, wing::QuicConnState.Closing, "connection transitioned to Closing");
    t.assert_eq(conn2.close_code, wing::QUIC_ERR_FLOW_CONTROL, "closed with FLOW_CONTROL_ERROR (0x03)");
}

fn main() {
    var runner = core::new_runner("QUIC Flow Control & RFC 9000 Invariants Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Connection Flow Control Budget (RFC 9000 §4.1)", test_connection_flow_control_budget);
    core::run_case(runner, "2. Monotonic MAX_DATA Limit Updates", test_monotonic_remote_max_data);
    core::run_case(runner, "3. Stream Flow Control Budget (RFC 9000 §4.1)", test_stream_flow_control_budget);
    core::run_case(runner, "4. Ingress Flow Control & FLOW_CONTROL_ERROR", test_ingress_flow_control_and_errors);
    core::run_case(runner, "5. RESET_STREAM Final Size Accounting (RFC 9000 §4.5)", test_reset_stream_flow_control_accounting);
    core::run_case(runner, "6. Window Update Auto-Generation (RFC 9000 §4.2)", test_window_update_thresholds);
    core::run_case(runner, "7. RFC 9000 Appendix A Packet Number Decoding", test_rfc9000_packet_number_decoding);
    core::run_case(runner, "8. QuicConnection Inbound Frame Demuxing", test_connection_datagram_demuxing);
    let ok = core::finish(runner);
    assert(ok);
}
