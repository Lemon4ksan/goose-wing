// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_flow_control_boundary.goose
// Verification of numerical boundary handling, arithmetic wrap prevention,
// and flow-control window calculation under edge conditions (RFC 9000 §4, §19).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

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

fn main() {
    test_recv_stream_arithmetic_wrap();
    test_send_arithmetic_wrap();
    test_limit_ceiling_and_reset();
    test_window_update_underflow_and_clamp();
}

// CHECK: FC_RECV_WRAP_PREVENTION: OK
// CHECK: FC_SEND_WRAP_PREVENTION: OK
// CHECK: FC_CEILING_AND_RESET: OK
// CHECK: FC_WINDOW_UPDATE_BOUNDS: OK
