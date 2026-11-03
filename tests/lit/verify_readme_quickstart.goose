// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_readme_quickstart.goose
// Verification suite ensuring all README.md Quick Start snippets compile and execute correctly.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_snippet_1_http_client() {
    var sess = wing::new_session("https://api.example.com") { s =>
        s.set_profile(wing::Profile.Wing);
        s.set_timeout_ms(5000);
        s.default_header("Accept", "application/json");
    };

    // Install mock route for offline CI execution
    wing::mock_route(sess, "GET", "https://api.example.com/v1/status", 200, "{\"status\":\"ok\"}");

    let res, err = sess.get("/v1/status");
    assert(err.ok());
    assert(res.is_success());
    assert(res.status_code == 200);
    assert(res.body[..] == "{\"status\":\"ok\"}");
    print("SNIPPET_1_CLIENT: OK");
}

fn test_snippet_2_http_server() {
    var server = wing::new_http_server("127.0.0.1", 8080);

    // Register routes with zero-allocation parameters
    server.add_get_route("/api/v1/users/{id}", 1);
    server.add_post_route("/api/v1/orders", 2);

    assert(server.port == 8080);
    print("SNIPPET_2_SERVER: OK");
}

fn test_snippet_3_websocket() {
    var hdr = wing::WsFrameHeader {
        fin:         true,
        opcode:      rfc::WS_OPCODE_TEXT,
        masked:      true,
        mask_key:    [0x12, 0x34, 0x56, 0x78],
        payload_len: 5,
    };

    var frame: u8[..64] = [];
    hdr.encode(frame);

    var payload: u8[..32] = [];
    payload.append("Hello");
    wing::mask_websocket_payload(payload[..], hdr.mask_key);
    frame.append(payload[..]);

    assert(frame.len > 0);
    print("SNIPPET_3_WEBSOCKET: OK");
}

fn main() {
    test_snippet_1_http_client();
    test_snippet_2_http_server();
    test_snippet_3_websocket();

    // CHECK: SNIPPET_1_CLIENT: OK
    // CHECK: SNIPPET_2_SERVER: OK
    // CHECK: SNIPPET_3_WEBSOCKET: OK
    // CHECK: README_QUICKSTART: ALL PASS
    print("README_QUICKSTART: ALL PASS");
}
