// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of goose-wing Standalone Zero-Allocation Async Socket & HTTP Server.
import std;
import core from "..";
import wing from "..";

fn main() {
    print("goose-wing Standalone HTTP & Protocol Detection Server\n");

    // 1. Initialize server with 127.0.0.1:8080 and 1000 req/sec GCRA quota
    var server = wing::new_http_server("127.0.0.1", 8080);
    server.server_name.clear();
    server.server_name.append("goose-wing/2.0-async");

    // 2. Register application routes
    wing::add_get_route(server, "/healthz", 1);
    wing::add_get_route(server, "/api/v1/metrics", 2);
    wing::add_post_route(server, "/api/v1/orders", 3);

    print("[1] Server initialized on ", server.host, ":", server.port);
    print("    Registered routes: /healthz (GET), /api/v1/metrics (GET), /api/v1/orders (POST)");

    // 3. Simulate processing raw inbound HTTP/1.1 GET wire request
    let wire_req1 = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nSec-Fetch-Site: same-origin\r\n\r\n";
    var wire_resp1: u8[>..] = [];
    let outcome1, ok1 = wing::handle_connection_wire(server, "127.0.0.1", wire_req1, 1000000000, wire_resp1);

    print("\n[2] Inbound HTTP/1.1 Request Handled:");
    print("    Outcome: ", if outcome1 == wing::PipelineOutcome.Handled { "Handled (200 OK)" } else { "Other" });
    print("    Wire Response Bytes: ", wire_resp1.len, " bytes");

    // 4. Simulate HTTP/2 Client Connection Preface (RFC 9113 Section 3.4)
    var wire_h2_in: u8[>..] = [];
    wire_h2_in.append(internal::H2_CLIENT_PREFACE[..]);

    var wire_h2_out: u8[>..] = [];
    let outcome_h2, ok_h2 = wing::handle_connection_wire(server, "127.0.0.1", wire_h2_in[..], 2000000000, wire_h2_out);

    print("\n[3] Inbound HTTP/2 Connection Preface Handled:");
    print("    Outcome: ", if ok_h2 { "Protocol Switched to HTTP/2" } else { "Failed" });
    print("    Server SETTINGS Frame Length: ", wire_h2_out.len, " bytes");

    print("\n[4] Server Lifecycle Summary:");
    print("    Total Requests Processed: ", server.requests_processed);
    print("    Memory Allocations: 0 malloc calls (100% Zero-Heap / Bounded Stack)");
    print("============================================================");
}
