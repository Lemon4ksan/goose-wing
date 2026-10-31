// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_zero_cost_oop.goose
// Verification of Zero-Cost OOP over Vulkan-style bricks:
// Closed transport polymorphism, Pool/Client integration, HeaderSpan zero-copy,
// and Push-Sink ChunkFsm streaming.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_transport_polymorphism() {
    print("=== Transport Polymorphism ===");
    var t_disc = wing::Transport.Disconnected;
    print(if t_disc.is_connected() { "disc_connected" } else { "disc_disconnected" });
    // CHECK: disc_disconnected

    var t_mock: wing::Transport = wing::Transport.Mock { route_idx: 1, cursor: 0 };
    print(if t_mock.is_connected() { "mock_connected" } else { "mock_disconnected" });
    // CHECK: mock_connected

    let sent = t_mock.send("hello");
    print(if sent == 5 { "mock_sent_5" } else { "mock_sent_err" });
    // CHECK: mock_sent_5

    t_mock.close();
    print(if t_mock.is_connected() { "closed_still_connected" } else { "closed_ok" });
    // CHECK: closed_ok
}

fn test_pool_and_connection() {
    print("=== Pool and Connection ===");
    var pool = wing::new_stream_pool();
    let key = wing::new_pool_key(
        wing::PoolScheme.Http,
        "api.example.com",
        80,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("api.example.com"),
        wing::TlsAndDnsPolicy { .. },
    );

    let t = wing::Transport.Mock { route_idx: 42, cursor: 100 };
    let cid = wing::register_connection(
        pool,
        key,
        wing::NegotiatedProtocol.Http11,
        t,
        "127.0.0.1",
        1,
        1000000,
    );
    print(if cid > 0 { "registered_ok" } else { "register_fail" });
    // CHECK: registered_ok

    let idx = pool.find_connection_index(cid);
    print(if idx >= 0 { "found_index_ok" } else { "found_index_fail" });
    // CHECK: found_index_ok

    if idx >= 0 {
        print(if pool.conns[idx].transport.is_connected() { "conn_transport_live" } else { "conn_transport_dead" });
        // CHECK: conn_transport_live
    }

    let closed = pool.close_pooled_connection(cid);
    print(if closed { "close_conn_ok" } else { "close_conn_fail" });
    // CHECK: close_conn_ok
}

fn test_span_headers_and_parsing() {
    print("=== Span Headers and Parsing ===");
    let raw_resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: wing-vulkan\r\n\r\n";
    var resp = wing::Response { .. };

    let ok_status = wing::parse_h1_status_line("HTTP/1.1 200 OK", resp);
    print(if ok_status && resp.status_code == 200 { "status_200_ok" } else { "status_fail" });
    // CHECK: status_200_ok

    let hdr_block: const u8[:] = "Content-Type: application/json\r\nServer: wing-vulkan\r\n";
    let ok_hdrs = wing::parse_h1_header_block(hdr_block, resp);
    print(if ok_hdrs && resp.spans.len == 2 { "spans_count_2" } else { "spans_fail" });
    // CHECK: spans_count_2

    let ct = resp.header("Content-Type");
    print(ct);
    // CHECK: application/json

    let srv = resp.header("Server");
    print(srv);
    // CHECK: wing-vulkan
}

fn test_push_sink_chunked_streaming() {
    print("=== Push-Sink Chunked Streaming ===");
    let chunked_wire: const u8[:] = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var dec = internal::new_chunk_fsm_decoder();
    var sink = wing::ArenaSink { max_bytes: 65536 };
    var out_body: u8[>..] = [];

    let st, consumed = wing::pump_chunk_fsm(dec, chunked_wire, sink, out_body);
    print(if st == internal::ChunkFsmStatus.Complete { "chunk_complete" } else { "chunk_incomplete" });
    // CHECK: chunk_complete

    print(out_body[..]);
    // CHECK: Wikipedia
}

fn main() {
    test_transport_polymorphism();
    test_pool_and_connection();
    test_span_headers_and_parsing();
    test_push_sink_chunked_streaming();
}
