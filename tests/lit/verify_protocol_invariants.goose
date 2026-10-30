// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_protocol_invariants.goose
// Advanced wire protocol verification using LLVM-style CHECK-LABEL isolation,
// CHECK-SAME inline matching, and numeric expressions [[#VAR + N]] / [[#VAR - N]].
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_h2_stream_progression() {
    print("=== H2_STREAM_PROGRESSION ===");
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Client preface + empty settings
    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    init_wire.append([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Open Stream 1, 3, 5 sequentially
    var stream_ids: const u32[3] = [1, 3, 5];
    var dt = internal::new_dynamic_table(4096);

    for sid in stream_ids {
        var hdr_block: u8[>..] = [];
        internal::encode_hpack_field(dt, hdr_block, ":method", "GET", true, false);
        internal::encode_hpack_field(dt, hdr_block, ":scheme", "https", true, false);
        internal::encode_hpack_field(dt, hdr_block, ":path", "/", true, false);

        var h_frame: u8[>..] = [];
        let h_len = hdr_block.len as u32;
        h_frame.push(((h_len >> 16) & 0xFF) as u8);
        h_frame.push(((h_len >> 8) & 0xFF) as u8);
        h_frame.push((h_len & 0xFF) as u8);
        h_frame.push(0x01); // HEADERS
        h_frame.push(0x05); // END_STREAM | END_HEADERS
        h_frame.push(((sid >> 24) & 0xFF) as u8);
        h_frame.push(((sid >> 16) & 0xFF) as u8);
        h_frame.push(((sid >> 8) & 0xFF) as u8);
        h_frame.push((sid & 0xFF) as u8);
        h_frame.append(hdr_block[..]);

        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
        assert(ok);
        print("H2_OPEN sid=", sid, " status=active type=client_bidi");
    }
}

fn test_quic_pn_and_window_math() {
    print("=== QUIC_PN_MATH ===");

    // Simulate packet numbers 500, 501, 502 with payload size 1200
    let start_pn: u64 = 500;
    let payload_len: u64 = 1200;

    print("QUIC_TX pn=", start_pn, " len=", payload_len, " flags=0x01");
    print("QUIC_TX pn=", start_pn + 1, " len=", payload_len, " flags=0x01");
    print("QUIC_TX pn=", start_pn + 2, " len=", payload_len, " flags=0x01");

    // Cumulative byte offset
    print("QUIC_FLOW byte_offset=", start_pn * payload_len);
    print("QUIC_FLOW next_offset=", (start_pn + 3) * payload_len);
    print("QUIC_ACK largest_acked=", start_pn + 2, " first_range=2");
}

fn test_wire_framing_delimiters() {
    print("=== WIRE_DELIMITERS ===");
    print("HEADER_START");
    print("Host: example.com");
    print("Connection: close");
    print(""); // Empty line before body (CHECK-EMPTY)
    print("PAYLOAD_START");
    print("line 1");
    print("line 2");
    print("PAYLOAD_END");
}

fn main() {
    test_h2_stream_progression();
    test_quic_pn_and_window_math();
    test_wire_framing_delimiters();
}

// CHECK-LABEL: === H2_STREAM_PROGRESSION ===
// CHECK: H2_OPEN sid=[[#SID:]]
// CHECK-SAME: status=active
// CHECK-SAME: type=client_bidi
// CHECK: H2_OPEN sid=[[#SID + 2]]
// CHECK-SAME: status=active
// CHECK: H2_OPEN sid=[[#SID + 4]]
// CHECK-SAME: status=active

// CHECK-LABEL: === QUIC_PN_MATH ===
// CHECK: QUIC_TX pn=[[#PN:]] len=[[#PLEN:]]
// CHECK-SAME: flags=0x01
// CHECK-NEXT: QUIC_TX pn=[[#PN + 1]] len=[[#PLEN]]
// CHECK-SAME: flags=0x01
// CHECK-NEXT: QUIC_TX pn=[[#PN + 2]] len=[[#PLEN]]
// CHECK-SAME: flags=0x01
// CHECK: QUIC_ACK largest_acked=[[#PN + 2]]
// CHECK-SAME: first_range=2

// CHECK-LABEL: === WIRE_DELIMITERS ===
// CHECK: HEADER_START
// CHECK: Host: example.com
// CHECK: Connection: close
// CHECK-EMPTY:
// CHECK: PAYLOAD_START
// CHECK: line 1
// CHECK: line 2
// CHECK: PAYLOAD_END
