// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_framer_h2_minsize.goose
// Repro test for RFC 9113 Section 4.2 minimum mandatory frame size violation.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== RFC 9113 FRAME_SIZE_ERROR REPRO ===");

    // Case 1: HEADERS with FLAG_PRIORITY (0x20) and length = 4 (needs at least 5 bytes: Exclusive + Stream Dep + Weight)
    let hdr_prio = internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PRIORITY | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_prio = internal::validate_frame_header_rules(hdr_prio);
    assert(err_prio == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_PRIO_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 2: HEADERS with FLAG_PADDED (0x08) and length = 0 (needs at least 1 byte Pad Length)
    let hdr_pad = internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_pad = internal::validate_frame_header_rules(hdr_pad);
    assert(err_pad == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_PAD_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 3: HEADERS with FLAG_PADDED | FLAG_PRIORITY (0x28) and length = 5 (needs at least 6 bytes: 1 Pad Length + 5 Priority)
    let hdr_both = internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_PRIORITY | rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let err_both = internal::validate_frame_header_rules(hdr_both);
    assert(err_both == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("HEADERS_BOTH_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 4: DATA with FLAG_PADDED (0x08) and length = 0 (needs at least 1 byte Pad Length)
    let hdr_data = internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_PADDED,
        stream_id:  1,
    };
    let err_data = internal::validate_frame_header_rules(hdr_data);
    assert(err_data == rfc::H2_ERR_FRAME_SIZE_ERROR);
    print("DATA_PAD_UNDERFLOW: FRAME_SIZE_ERROR");

    // Case 5: on_ingress_frame_header MUST reject undersized HEADERS and NOT open a new stream
    var conn = internal::new_h2_connection(0);
    let ingress_err = internal::on_ingress_frame_header(conn, hdr_prio, 0);
    assert(ingress_err == rfc::H2_ERR_FRAME_SIZE_ERROR);
    assert(conn.active_stream_count == 0);
    let s_idx, found = internal::find_h2_stream_idx(conn, 1);
    assert(!found);
    print("CONN_INGRESS_UNDERFLOW_BLOCKED: FRAME_SIZE_ERROR");

    print("ALL_FRAME_SIZE_TESTS: OK");
}

// CHECK: === RFC 9113 FRAME_SIZE_ERROR REPRO ===
// CHECK: HEADERS_PRIO_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: HEADERS_PAD_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: HEADERS_BOTH_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: DATA_PAD_UNDERFLOW: FRAME_SIZE_ERROR
// CHECK: CONN_INGRESS_UNDERFLOW_BLOCKED: FRAME_SIZE_ERROR
// CHECK: ALL_FRAME_SIZE_TESTS: OK
