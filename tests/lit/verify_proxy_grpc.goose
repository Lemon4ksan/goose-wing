// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_proxy_grpc.goose
// Verification of Reverse Proxy streaming forwarding, Load Balancer flapping mitigation,
// GCRA multi-cell burst guard, gRPC bidirectional LPM streaming, and Protowire status serialization.
//
// RUN: goose check %s
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_proxy_splice_and_userspace_streaming() {
    let tcp_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.PlainTcp, false);
    let connect_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.Http1Connect, false);
    let tls_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.Tls, true);
    let ws_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.WebSocket, false);
    let wt_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.WebTransport, true);

    print(
        "PROXY_SPLICE_ELIGIBILITY: tcp=", tcp_splice,
        " connect=", connect_splice,
        " tls=", tls_splice,
        " ws=", ws_splice,
        " wt=", wt_splice, "\n",
    );
    // CHECK: PROXY_SPLICE_ELIGIBILITY: tcp=true connect=true tls=false ws=false wt=false

    // Userspace zero-copy ring-buffer streaming (incoming_slice / advance_read)
    var src_ring = wing::ProxyStreamRing { .. };
    var dst_ring = wing::ProxyStreamRing { .. };

    let ok_feed1 = wing::feed_stream_chunk(src_ring, "PING");
    assert(ok_feed1);
    let slice1 = wing::incoming_slice(src_ring);
    assert(slice1 == "PING");

    // WebSocket RFC 6455 §5.3 XOR masking transfer
    let ws_mask: u8[4] = [0x11, 0x22, 0x33, 0x44];
    let xfer_len, ok_xfer = wing::forward_userspace_stream_chunk(
        src_ring,
        dst_ring,
        wing::ProxyTransportKind.WebSocket,
        ws_mask,
    );
    assert(ok_xfer && xfer_len == 4);
    assert(wing::incoming_slice(src_ring).len == 0);

    let dst_view = wing::incoming_slice(dst_ring);
    assert(dst_view.len == 4);
    assert(dst_view[0] == ('P' ^ 0x11));
    assert(dst_view[1] == ('I' ^ 0x22));
    assert(dst_view[2] == ('N' ^ 0x33));
    assert(dst_view[3] == ('G' ^ 0x44));
    assert(wing::advance_read(dst_ring, 4));
    assert(wing::incoming_slice(dst_ring).len == 0);

    // Overflow rejection (Invariant 13): fill 16380 bytes, then attempt 8 bytes (exceeds 16384 cap)
    var full_ring = wing::ProxyStreamRing { .. };
    var chunk_8k: u8[..8192] = [];
    for _ in 8190 {
        chunk_8k.push('A');
    }
    assert(wing::feed_stream_chunk(full_ring, chunk_8k[..])); // 8190
    assert(wing::feed_stream_chunk(full_ring, chunk_8k[..])); // 16380
    let ok_overflow = wing::feed_stream_chunk(full_ring, "12345678");
    if ok_overflow {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }

    print(
        "PROXY_RING_STREAMING: xfer_len=", xfer_len,
        " drained=", (wing::incoming_slice(dst_ring).len == 0),
        " overflow_rejected=", !ok_overflow, "\n",
    );
    // CHECK: PROXY_RING_STREAMING: xfer_len=4 drained=true overflow_rejected=true
}

fn test_load_balancer_flapping_and_gcra_burst_guard() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 0);
    wing::add_upstream_target(cluster, "10.0.0.10", 8080);
    wing::set_target_health_thresholds(cluster, 0, 2, 3);

    // 2 consecutive failures (< unhealthy_threshold=3) -> stays Up
    let st_f1 = wing::record_probe_result(cluster.targets[0], false);
    let st_f2 = wing::record_probe_result(cluster.targets[0], false);
    let still_up = (st_f1 == wing::UpstreamHealthState.Up && st_f2 == wing::UpstreamHealthState.Up);

    // 3rd consecutive failure -> trips to Down
    let st_f3 = wing::record_probe_result(cluster.targets[0], false);
    let tripped_down = (st_f3 == wing::UpstreamHealthState.Down && !cluster.targets[0].is_healthy);

    // 1st consecutive success in Down -> transitions to Probing (Half-Open), not yet healthy
    let st_s1 = wing::record_probe_result(cluster.targets[0], true);
    let in_probing = (st_s1 == wing::UpstreamHealthState.Probing && !cluster.targets[0].is_healthy);

    // 2nd consecutive success (reaches healthy_threshold=2) -> closes circuit to Up
    let st_s2 = wing::record_probe_result(cluster.targets[0], true);
    let recovered_up = (st_s2 == wing::UpstreamHealthState.Up && cluster.targets[0].is_healthy);

    print(
        "LB_FLAP_HYSTERESIS: still_up_at_2=", still_up,
        " tripped_at_3=", tripped_down,
        " half_open_at_1=", in_probing,
        " closed_at_2=", recovered_up, "\n",
    );
    // CHECK: LB_FLAP_HYSTERESIS: still_up_at_2=true tripped_at_3=true half_open_at_1=true closed_at_2=true

    // Multi-cell GCRA burst check: reject cost > (max_burst + 1) without mutating TAT
    let cfg = wing::new_gcra_config(10, 2); // T=100ms, tau=200ms, limit_window=300ms (max 3 cells)
    var cell = wing::GcraTatCell { tat_ns: 1000000000 };
    let peek_over = wing::gcra_peek(cfg, cell, 10, 1000000000);
    let dec_over = wing::gcra_check(cfg, cell, 10, 1000000000);
    print(
        "GCRA_MULTI_CELL_GUARD: allowed=", (dec_over.allowed || peek_over.allowed),
        " tat_preserved=", (cell.tat_ns == 1000000000), "\n",
    );
    // CHECK: GCRA_MULTI_CELL_GUARD: allowed=false tat_preserved=true
}

fn test_grpc_bidi_streaming_and_status_details() {
    var stream = wing::H2Stream {
        stream_id:   1,
        state:       wing::H2StreamState.Open,
        send_window: 65535,
        recv_window: 65535,
        active:      true,
        ..
    };

    var raw_in: u8[..64] = [];
    wing::encode_grpc_lpm("hello", raw_in, false);
    wing::encode_grpc_lpm("world", raw_in, false);

    var reader = wing::GrpcLpmReader { .. };
    var writer = wing::GrpcLpmWriter { .. };

    let ok_feed = wing::feed_grpc_lpm_reader(reader, raw_in[..]);
    let ok_bidi = wing::dispatch_grpc_bidi_streaming(stream, reader, writer);

    // Verify truncated LPM frame is rejected
    let truncated: u8[7] = [0x00, 0x00, 0x00, 0x00, 0x05, 'a', 'b'];
    var bad_reader = wing::GrpcLpmReader { .. };
    let ok_trunc = wing::feed_grpc_lpm_reader(bad_reader, truncated[..]);

    print(
        "GRPC_BIDI_LPM: feed_ok=", ok_feed,
        " dispatch_ok=", ok_bidi,
        " out_msgs=", writer.message_count,
        " out_bytes=", writer.wire_buf.len,
        " trunc_rejected=", !ok_trunc, "\n",
    );
    // CHECK: GRPC_BIDI_LPM: feed_ok=true dispatch_ok=true out_msgs=2 out_bytes=20 trunc_rejected=true

    // Verify build_grpc_status_details byte-for-byte Protobuf wire encoding:
    // code = 3 (INVALID_ARGUMENT) -> 0x08 0x03
    // msg = "bad" (len 3) -> 0x12 0x03 'b' 'a' 'd'
    var status_buf: u8[16] = [0; 16];
    let written, ok_status = wing::build_grpc_status_details(3, "bad", status_buf[..]);
    let wire_match = (written == 7 &&
        status_buf[0] == 0x08 &&
        status_buf[1] == 0x03 &&
        status_buf[2] == 0x12 &&
        status_buf[3] == 0x03 &&
        status_buf[4] == 'b' &&
        status_buf[5] == 'a' &&
        status_buf[6] == 'd');

    // Small buffer capacity overflow rejection (Invariant 13)
    var tiny_buf: u8[4] = [0; 4];
    let tiny_written, ok_tiny = wing::build_grpc_status_details(3, "bad", tiny_buf[..]);
    if ok_tiny {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }

    print(
        "GRPC_STATUS_DETAILS: ok=", ok_status,
        " len=", written,
        " wire_match=", wire_match,
        " tiny_rejected=", (!ok_tiny && tiny_written == 0), "\n",
    );
    // CHECK: GRPC_STATUS_DETAILS: ok=true len=7 wire_match=true tiny_rejected=true
    // CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
}

fn main() {
    test_proxy_splice_and_userspace_streaming();
    test_load_balancer_flapping_and_gcra_burst_guard();
    test_grpc_bidi_streaming_and_status_details();
}
